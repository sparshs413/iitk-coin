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

	rows, _ := database.InitalizeDatabase().Query("SELECT id, username, name, rollno, password FROM user")

	var id int
	var username string
	var name string
	var rollno string
	var password string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password)
		
		fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/signup", controllers.Signup)
	mux.HandleFunc("/login", controllers.Login)
	mux.Handle("/secretPage", controllers.IsAuthorized(controllers.SecretPage))

	http.ListenAndServe(":8080", mux)
}
