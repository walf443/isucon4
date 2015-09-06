package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	redis "gopkg.in/redis.v3"
)

var (
	ErrBannedIP      = errors.New("Banned IP")
	ErrLockedUser    = errors.New("Locked user")
	ErrUserNotFound  = errors.New("Not found user")
	ErrWrongPassword = errors.New("Wrong password")
)

type loginLog struct {
	createdAt  time.Time
	userId     sql.NullInt64
	login      string
	remoteAddr string
	succ       int
}

var rd *redis.Client
var mu *sync.Mutex
var chLog chan loginLog
var chDone chan bool

func init() {
	rd = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	mu = new(sync.Mutex)
	chLog = make(chan loginLog, 10000)
	chDone = make(chan bool)
	go insertLoginLogs()
}

func insertLoginLogs() {
	for {
		log, more := <-chLog
		if more {
			_, err := db.Exec(
				"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
					"VALUES (?,?,?,?,?)",
				log.createdAt, log.userId, log.login, log.remoteAddr, log.succ,
			)
			if err != nil {
				panic(err.Error())
			}
		} else {
			chDone <- true
			return
		}
	}
}

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) error {
	succ := 0
	if succeeded {
		succ = 1
	}

	createdAt := time.Now()

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true

		mu.Lock()
		if succeeded {
			resetUserFailCount(user.ID)
			resetIpFailCount(remoteAddr)

			j, err := json.Marshal(LastLogin{login, remoteAddr, createdAt})
			if err != nil {
				panic(err.Error())
			}
			rd.LPush(userLoginHistoryKey(user.ID), string(j))
		} else {
			incrUserFailCount(user.ID)
			incrIpFailCount(remoteAddr)
		}
		mu.Unlock()
	}

	chLog <- loginLog{createdAt, userId, login, remoteAddr, succ}
	//_, err := db.Exec(
	//"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
	//"VALUES (?,?,?,?,?)",
	//time.Now(), userId, login, remoteAddr, succ,
	//)

	//return err
	return nil
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	var ni sql.NullInt64
	row := db.QueryRow(
		"SELECT COUNT(1) AS failures FROM login_log WHERE "+
			"user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND "+
			"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
		user.ID, user.ID,
	)
	err := row.Scan(&ni)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return UserLockThreshold <= int(ni.Int64), nil
}

func isLockedUser2(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}

	val, err := rd.Get(userFailCountKey(user.ID)).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatal(err.Error())
		return false, err
	}

	return UserLockThreshold <= i, nil
}

func userFailCountKey(userID int) string {
	return fmt.Sprintf("user_fail_count_%d", userID)
}

func resetUserFailCount(userID int) {
	rd.Set(userFailCountKey(userID), 0, 0)
}

func incrUserFailCount(userID int) {
	rd.Incr(userFailCountKey(userID))
}

func isBannedIP(ip string) (bool, error) {
	var ni sql.NullInt64
	row := db.QueryRow(
		"SELECT COUNT(1) AS failures FROM login_log WHERE "+
			"ip = ? AND id > IFNULL((select id from login_log where ip = ? AND "+
			"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
		ip, ip,
	)
	err := row.Scan(&ni)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return IPBanThreshold <= int(ni.Int64), nil
}

func isBannedIP2(ip string) (bool, error) {
	val, err := rd.Get(ipFailCountKey(ip)).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatal(err.Error())
		return false, err
	}

	return IPBanThreshold <= i, nil
}

func resetIpFailCount(ip string) {
	rd.Set(ipFailCountKey(ip), 0, 0)
}

func incrIpFailCount(ip string) {
	rd.Incr(ipFailCountKey(ip))
}

func ipFailCountKey(ip string) string {
	return fmt.Sprintf("ip_fail_count_%s", ip)
}

func userLoginHistoryKey(userID int) string {
	return fmt.Sprintf("user_login_history_%d", userID)
}

func attemptLogin(req *http.Request) (*User, error) {
	succeeded := false
	user := &User{}

	loginName := req.PostFormValue("login")
	password := req.PostFormValue("password")

	remoteAddr := req.RemoteAddr
	if xForwardedFor := req.Header.Get("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = xForwardedFor
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)
	}()

	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE login = ?",
		loginName,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	switch {
	case err == sql.ErrNoRows:
		user = nil
	case err != nil:
		return nil, err
	}

	mu.Lock()
	if banned, _ := isBannedIP2(remoteAddr); banned {
		mu.Unlock()
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser2(user); locked {
		mu.Unlock()
		return nil, ErrLockedUser
	}
	mu.Unlock()

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.PasswordHash != calcPassHash(password, user.Salt) {
		return nil, ErrWrongPassword
	}

	succeeded = true
	return user, nil
}

func getCurrentUser(userId interface{}) *User {
	user := &User{}
	row := db.QueryRow(
		"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
		userId,
	)
	err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

	if err != nil {
		return nil
	}

	return user
}

func bannedIPs() []string {
	ips := []string{}

	rows, err := db.Query(
		"SELECT ip FROM "+
			"(SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) "+
			"AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?",
		IPBanThreshold,
	)

	if err != nil {
		return ips
	}

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err := rows.Scan(&ip); err != nil {
			return ips
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return ips
	}

	rowsB, err := db.Query(
		"SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip",
	)

	if err != nil {
		return ips
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var ip string
		var lastLoginId int

		if err := rows.Scan(&ip, &lastLoginId); err != nil {
			return ips
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id",
			ip, lastLoginId,
		).Scan(&count)

		if err != nil {
			return ips
		}

		if IPBanThreshold <= count {
			ips = append(ips, ip)
		}
	}
	if err := rowsB.Err(); err != nil {
		return ips
	}

	return ips
}

func lockedUsers() []string {
	userIds := []string{}

	rows, err := db.Query(
		"SELECT user_id, login FROM "+
			"(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) "+
			"AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?",
		UserLockThreshold,
	)

	if err != nil {
		return userIds
	}

	defer rows.Close()
	for rows.Next() {
		var userId int
		var login string

		if err := rows.Scan(&userId, &login); err != nil {
			return userIds
		}
		userIds = append(userIds, login)
	}
	if err := rows.Err(); err != nil {
		return userIds
	}

	rowsB, err := db.Query(
		"SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id",
	)

	if err != nil {
		return userIds
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var userId int
		var login string
		var lastLoginId int

		if err := rowsB.Scan(&userId, &login, &lastLoginId); err != nil {
			return userIds
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id",
			userId, lastLoginId,
		).Scan(&count)

		if err != nil {
			return userIds
		}

		if UserLockThreshold <= count {
			userIds = append(userIds, login)
		}
	}
	if err := rowsB.Err(); err != nil {
		return userIds
	}

	return userIds
}

func resetRedis() {
	log.Printf("initializing redis")
	rd.FlushAll()

	rows, err := db.Query("SELECT created_at, user_id, login, ip, succeeded FROM login_log ORDER BY id ASC")

	multi := rd.Multi()
	defer func() {
		multi.Close()
	}()

	_, err = multi.Exec(func() error {
		for rows.Next() {
			var createdAt time.Time
			var userId int
			var login string
			var ip string
			var succeeded int

			if err := rows.Scan(&createdAt, &userId, &login, &ip, &succeeded); err != nil {
				return err
			}

			//log.Printf("userId:%d, ip:%s, succeeded:%d", userId, ip, succeeded)

			if succeeded > 0 {
				multi.Set(userFailCountKey(userId), 0, 0)
				multi.Set(ipFailCountKey(ip), 0, 0)
				j, err := json.Marshal(LastLogin{login, ip, createdAt})
				if err != nil {
					panic(err.Error())
				}
				multi.LPush(userLoginHistoryKey(userId), string(j))
			} else {
				multi.Incr(userFailCountKey(userId))
				multi.Incr(ipFailCountKey(ip))
			}
		}
		return nil
	})

	if err != nil {
		panic(err.Error())
	}
	log.Printf("done initializing redis")
}

func lookupLoginHistory(userID int, index int) (*LastLogin, error) {
	j, err := rd.LIndex(userLoginHistoryKey(userID), 1).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var lastLogin LastLogin
	err = json.Unmarshal([]byte(j), &lastLogin)
	if err != nil {
		return nil, err
	}
	log.Println(lastLogin)
	return &lastLogin, nil
}
