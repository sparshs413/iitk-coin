package database

import "database/sql"

func InitalizeDatabase() *sql.DB {
	db, _ := sql.Open("sqlite3", "db/users.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,username TEXT, name TEXT, rollno INTEGER, password TEXT)")
	statement.Exec()

	return db
}