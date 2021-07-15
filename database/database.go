package database

import "database/sql"

func InitalizeDatabase() *sql.DB {
	db, _ := sql.Open("sqlite3", "db/users.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,username TEXT, name TEXT, rollno INTEGER, password TEXT, coins INTEGER, permissionLevel INTEGER, competitionsParticipated INTEGER)")
	statement.Exec()

	statement1, _ := db.Prepare("CREATE TABLE IF NOT EXISTS redeem (id INTEGER PRIMARY KEY, rollno INTEGER, coins INTEGER, itemName TEXT, status INTEGER)")
	statement1.Exec()

	return db
}

func InitalizeTransactionHistoryDatabase() *sql.DB {
	db, _ := sql.Open("sqlite3", "db/transactionHistory.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS transactionHistory (id INTEGER PRIMARY KEY, typeOfTransaction TEXT, transferToRollno INTEGER, senderRollNo INTEGER, coins INTEGER, timestamp TEXT)")
	statement.Exec()

	return db
}