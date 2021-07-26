package main

import (
	"iitk-coin/controllers"
	"iitk-coin/database"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	database.InitalizeDatabase()
	database.InitalizeTransactionHistoryDatabase()

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

	log.Println("Starting server. Listening on http://localhost:8080")

	// port 8080
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err)
	}
}

