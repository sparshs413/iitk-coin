package main

import (
	"iitk-coin/controllers"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// fmt.Println("Users DB")
	// rows, _ := database.InitalizeDatabase().Query("SELECT id, username, name, rollno, password, coins, permissionLevel, competitionsParticipated FROM user")

	// var id int
	// var username string
	// var name string
	// var rollno string
	// var password string
	// var coins string
	// var permissionLevel string
	// var competitionsParticipated string

	// for rows.Next() {
	// 	rows.Scan(&id, &username, &name, &rollno, &password, &coins, &permissionLevel, &competitionsParticipated)
		
	// 	fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username + " " + coins + " " + permissionLevel + " " + competitionsParticipated)
	// }

	// fmt.Println("\n" + "Transfer DB")
	
	// rows1, _ := database.InitalizeTransactionHistoryDatabase().Query("SELECT id, typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp FROM transactionHistory")

	// var id1 int
	// var typeOfTransaction string
	// var transferToRollno string
	// var senderRollNo string
	// var timestamp string

	// for rows1.Next() {
	// 	rows1.Scan(&id1, &typeOfTransaction, &transferToRollno, &senderRollNo, &coins, &timestamp)
		
	// 	fmt.Println(strconv.Itoa(id1) + ": " + senderRollNo + " " + transferToRollno + " " + coins + " " + typeOfTransaction + " " + timestamp)
	// }

	// fmt.Println("\n" + "Redeem DB")
	// rows2, _ := database.InitalizeDatabase().Query("SELECT id, rollno, coins, itemName, status FROM redeem")

	// var id2 int
	// var rollno1 string
	// var coins1 string
	// var status string
	// var itemName string

	// for rows2.Next() {
	// 	rows2.Scan(&id2, &rollno1, &coins1, &itemName, &status)
		
	// 	fmt.Println(strconv.Itoa(id2) + ": " + rollno1 + " " + coins1 + " " + itemName + " " + status)
	// }


	mux := http.NewServeMux()

	mux.HandleFunc("/signup", controllers.Signup)
	mux.HandleFunc("/login", controllers.Login)
	mux.Handle("/giveCoins", controllers.IsAuthorized(controllers.GiveCoins))
	mux.Handle("/transferCoins", controllers.IsAuthorized(controllers.TransferCoins))
	mux.Handle("/balance", controllers.IsAuthorized(controllers.Balance))
	mux.Handle("/secretPage", controllers.IsAuthorized(controllers.SecretPage))
	mux.Handle("/redeem", controllers.IsAuthorized(controllers.Redeem))
	mux.Handle("/approveRequest", controllers.IsAuthorized(controllers.ApproveRequest))
	mux.Handle("/showUnapprovedRequest", controllers.IsAuthorized(controllers.ShowUnapprovedRequest))

	http.ListenAndServe(":8080", mux)
}

