package models

import (
	"database/sql"
	"encoding/json"
	"log"
	"strconv"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var MySigningKey = []byte("pingala")  // Can be taken from a .env file

type User struct {
	Username string `json:"username"` 
	Rollno  int  `json:"rollno"`
	Name string  `json:"name"` 
	Password string `json:"password"` 
	Coins int `json:"coins"`
	PermissionsLevel int `json:"permissions"`
	CompetitionsParticipated int `json:"competitionsParticipated"`
}

type LoginCred struct {
	Rollno int `json:"rollno"`
	Password string `json:"password"`
}

type Response struct { 
	Message string `json:"message"` 
}

type RetrieveBalance struct { 
	Rollno  int  `json:"rollno"`
	Coins int `json:"coins"`
}

type UpdateCoins struct { 
	Rollno  int  `json:"rollno"`
	Coins int `json:"coins"`
}

type TransferCoins struct { 
	SenderRollno int `json:"senderRollno"`
	ReceiverRollno  int  `json:"receiverRollno"`
	SenderCoins int `json:"senderCoins"`
	ReceiverCoins int `json:"receiverCoins"`
	Coins int `json:"transferCoins"`
}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}

func AddTransaction(db *sql.DB, typeOfTransaction string, transferToRollno int, senderRollNo int, coins int, timestamp string) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO transactionHistory (typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp) VALUES (?, ?, ?, ?, ?)")
	_, err := stmt.Exec(typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func AddUser(db *sql.DB, username string, name string, rollno int, password string, coins int, permissionLevel int, competitionsParticipated int) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO user (username, name, rollno, password, coins, permissionLevel, competitionsParticipated) VALUES (?, ?, ?, ?, ?, ?, ?)")
	_, err := stmt.Exec(username, name, rollno, password, coins, permissionLevel, competitionsParticipated)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func UpdateUser(db *sql.DB, id int, rollno int, coins int) bool {	
	sid := strconv.Itoa(id)
	scoins := strconv.Itoa(coins)
	// srollno := strconv.Itoa(rollno)  
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update user set coins=? where id=?")
	_, err := stmt.Exec(scoins, sid)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func UpdatePermissions(db *sql.DB, id int, permissions int) bool {	
	sid := strconv.Itoa(id)
	spermissions := strconv.Itoa(permissions)
	// srollno := strconv.Itoa(rollno)  
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update user set permissionLevel=? where id=?")
	_, err := stmt.Exec(spermissions, sid)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func UpdateNumCompetitions(db *sql.DB, id int, rollno int, competitions int) bool {	
	sid := strconv.Itoa(id)
	scompetitions := strconv.Itoa(competitions)
	// srollno := strconv.Itoa(rollno)  
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update user set competitionsParticipated=? where id=?")
	_, err := stmt.Exec(scompetitions, sid)
	if err != nil {
		CheckErr(err)
		return false
	}
	tx.Commit()

	return true
}

func GetCoins(db *sql.DB, rollno int) int {
	query := db.QueryRow("select coins from user where rollno=$1", rollno)
	var coins int
	query.Scan(&coins)

	return coins
}

func GetUserId(db *sql.DB, rollno int) int {
	query := db.QueryRow("select id from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
}

func GetUserPermission(db *sql.DB, rollno int) int {
	query := db.QueryRow("select permissionLevel from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
}

func GetNumCompetiton(db *sql.DB, rollno int) int {
	query := db.QueryRow("select competitionsParticipated from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
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

func ExtractClaims(tokenStr string) (jwt.MapClaims, bool) {
	// hmacSecretString := // Value
	hmacSecret := MySigningKey
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		 // check token signing method etc
		 return hmacSecret, nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return nil, false
	}
}

func IsJSON(s string) bool {
    var js map[string]interface{}
    return json.Unmarshal([]byte(s), &js) == nil
}