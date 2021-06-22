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

	rows, _ := database.InitalizeDatabase().Query("SELECT id, username, name, rollno, password, coins FROM user")

	var id int
	var username string
	var name string
	var rollno string
	var password string
	var coins string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password, &coins)
		
		fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username + " " + coins)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/signup", controllers.Signup)
	mux.HandleFunc("/login", controllers.Login)
	mux.HandleFunc("/giveCoins", controllers.GiveCoins)
	mux.HandleFunc("/transferCoins", controllers.TransferCoins)
	mux.HandleFunc("/balance", controllers.Balance)
	mux.Handle("/secretPage", controllers.IsAuthorized(controllers.SecretPage))

	http.ListenAndServe(":8080", mux)
}
