package models

import (
	"database/sql"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var MySigningKey = []byte("pingala")  // Can be taken from a .env file

type User struct {
	Username string `json:"username"` 
	Rollno  int  `json:"rollno"`
	Name string  `json:"name"` 
	Password string `json:"password"` 
}

type LoginCred struct {
	Rollno int `json:"rollno"`
	Password string `json:"password"`
}

type Response struct { 
	Message string `json:"message"` 
}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}

func AddUser(db *sql.DB, username string, name string, rollno int, password string) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO user (username, name, rollno, password) VALUES (?, ?, ?, ?)")
	_, err := stmt.Exec(username, name, rollno, password)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func HashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func ComparePasswords(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}
	
	return true
}