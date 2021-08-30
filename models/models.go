package models

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	gomail "gopkg.in/mail.v2"

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

type RedeemReqCust struct { 
	Id int `json:"id"`
	Rollno int `json:"rollno"`
	Coins int `json:"coins"`
	ItemName string `json:"itemname"` 
}

type AcceptReq struct { 
	Id int `json:"id"`
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

func AddRedeemRequest(db *sql.DB, name string, rollno int, coins int) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO redeem (rollno, coins, itemName, status) VALUES (?, ?, ?, ?)")
	_, err := stmt.Exec(rollno, coins, name, 1)
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

func UpdateRequestStatus(db *sql.DB, id int, status int) bool {
	sid := strconv.Itoa(id)
	sstatus := strconv.Itoa(status)
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update redeem set status=? where id=?")
	_, err := stmt.Exec(sstatus, sid)
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

func GetReqData(db *sql.DB, id int) (string, string, string) {
	query := db.QueryRow("select rollno, coins, itemName, status from redeem where id=$1", id)
	var rollno string
	var coins string
	var status string
	var itemName string

	query.Scan(&rollno, &coins, &itemName, &status)

	return rollno, coins, status
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

func SendOtp(rollno int) bool {
	srollno := strconv.Itoa(rollno)
	m := gomail.NewMessage()
	m.SetHeader("From", "sparshs@iitk.ac.in")
	m.SetHeader("To", srollno + "@iitk.ac.in")
	m.SetHeader("Subject", "Gomail test subject")
	m.SetBody("text/plain", "This is Gomail test body")
	d := gomail.NewDialer("mmtp.iitk.ac.in", 25, "sparshs@iitk.ac.in", "Myr@ndOmPaSswOrD")
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		panic(err)
	}

	return true
}

func SendResponse(status int, message string, w http.ResponseWriter) {
	if status == 400 {
		w.WriteHeader(http.StatusBadRequest)
	} else if status == 401 {
		w.WriteHeader(http.StatusUnauthorized)
	} else if status == 403 {
		w.WriteHeader(http.StatusForbidden)
	} else if status == 404 {
		w.WriteHeader(http.StatusNotFound)
	} else if status == 409 {
		w.WriteHeader(http.StatusConflict)
	} else if status == 500 {
		w.WriteHeader(http.StatusInternalServerError)
	} else if status == 200 {
		w.WriteHeader(http.StatusOK)
	} else if status == 406 {
		w.WriteHeader(http.StatusNotAcceptable)
	}

	response := Response {
		Message: message,
	}

	json.NewEncoder(w).Encode(response) 
}