package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// 登録ユーザをハードコード
var user = User{
	id:       1111,
	name:     "hoge",
	password: "password",
}

type userInfo struct {
	id       int
	name     string
	password string
}

func getUser(userId int, pass string) (*userInfo, error) {
	filename := "users.json"
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var u userInfo
	if err := json.Unmarshal(file, &u); err != nil {
		return nil, err
	}
	if u.id == userId {
		if u.password == pass {
			return &u, err
		}
	}
	return nil, fmt.Errorf("Invalid userID: %d", userId)
}
