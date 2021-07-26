package database

import (
	"database/sql"
	"log"
)

func InitalizeDatabase() *sql.DB {
	db, _ := sql.Open("sqlite3", "db/users.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,username TEXT, name TEXT, rollno INTEGER, password TEXT, coins INTEGER, permissionLevel INTEGER, competitionsParticipated INTEGER)")
	log.Println("User Database opened and table created (if not existed) successfully!")
	statement.Exec()

	statement1, _ := db.Prepare("CREATE TABLE IF NOT EXISTS redeem (id INTEGER PRIMARY KEY, rollno INTEGER, coins INTEGER, itemName TEXT, status INTEGER)")
	log.Println("Wallet Database opened and table created (if not existed) successfully!")
	statement1.Exec()

	return db
}

func InitalizeTransactionHistoryDatabase() *sql.DB {
	db, _ := sql.Open("sqlite3", "db/transactionHistory.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS transactionHistory (id INTEGER PRIMARY KEY, typeOfTransaction TEXT, transferToRollno INTEGER, senderRollNo INTEGER, coins INTEGER, timestamp TEXT)")
	log.Println("Transaction Database opened and table created (if not existed) successfully!")
	statement.Exec()

	return db
}