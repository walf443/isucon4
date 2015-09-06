package main

import (
	"time"
)

type User struct {
	ID           int
	Login        string
	PasswordHash string
	Salt         string

	LastLogin *LastLogin
}

type LastLogin struct {
	Login     string    `json:login`
	IP        string    `json:ip`
	CreatedAt time.Time `json:created_at`
}

func (u *User) getLastLogin() *LastLogin {
	rows, err := db.Query(
		"SELECT login, ip, created_at FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2",
		u.ID,
	)

	if err != nil {
		return nil
	}

	defer rows.Close()
	for rows.Next() {
		u.LastLogin = &LastLogin{}
		err = rows.Scan(&u.LastLogin.Login, &u.LastLogin.IP, &u.LastLogin.CreatedAt)
		if err != nil {
			u.LastLogin = nil
			return nil
		}
	}

	return u.LastLogin
}

func (u *User) getLastLogin2() *LastLogin {
	lastLogin, err := lookupLoginHistory(u.ID, 1)
	if err != nil {
		u.LastLogin = nil
		return nil
	}
	if lastLogin != nil {
		u.LastLogin = lastLogin
	} else {
		// 取れなければ直近のログを取る
		lastLogin, err = lookupLoginHistory(u.ID, 0)
		if err != nil {
			u.LastLogin = nil
			return nil
		}
	}
	return lastLogin
}
