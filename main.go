package main

import (
	"fmt"
	"iitk-coin/controllers"
	"net/http"
	"strconv"

	"iitk-coin/database"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	rows, _ := database.InitalizeDatabase().Query("SELECT id, username, name, rollno, password, coins, permissionLevel, competitionsParticipated FROM user")

	var id int
	var username string
	var name string
	var rollno string
	var password string
	var coins string
	var permissionLevel string
	var competitionsParticipated string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password, &coins, &permissionLevel, &competitionsParticipated)
		
		fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username + " " + coins + " " + permissionLevel + " " + competitionsParticipated)
	}
	
	rows1, _ := database.InitalizeTransactionHistoryDatabase().Query("SELECT id, typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp FROM transactionHistory")

	var id1 int
	var typeOfTransaction string
	var transferToRollno string
	var senderRollNo string
	var timestamp string

	for rows1.Next() {
		rows1.Scan(&id1, &typeOfTransaction, &transferToRollno, &senderRollNo, &coins, &timestamp)
		
		fmt.Println(strconv.Itoa(id1) + ": " + senderRollNo + " " + transferToRollno + " " + coins + " " + typeOfTransaction + " " + timestamp)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/signup", controllers.Signup)
	mux.HandleFunc("/login", controllers.Login)
	mux.Handle("/giveCoins", controllers.IsAuthorized(controllers.GiveCoins))
	mux.Handle("/transferCoins", controllers.IsAuthorized(controllers.TransferCoins))
	mux.Handle("/balance", controllers.IsAuthorized(controllers.Balance))
	mux.Handle("/secretPage", controllers.IsAuthorized(controllers.SecretPage))

	http.ListenAndServe(":8080", mux)
}
