package main

import (
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func deleteUser(db *sql.DB, id2 int) {
	sid := strconv.Itoa(id2) 
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("delete from user where id=?")
	_, err := stmt.Exec(sid)
	checkErr(err)
	tx.Commit()
  }

func addUser(db *sql.DB, rollno int, name string) {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO user (rollno, name) VALUES (?, ?)")
	_, err := stmt.Exec(rollno, name)
	checkErr(err)
	tx.Commit()
  }

func main() {
	db, _ := sql.Open("sqlite3", "db/users.db")

	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,rollno INTEGER, name TEXT)")

	statement.Exec()

	addUser(db, 190862, "Demos User")

	// deleteUser(db, 2)  // Can be used to delete a user from the database with a ID

	rows, _ := db.Query("SELECT id, rollno, name FROM user")

	var id int
	var rollno int
	var name string

	for rows.Next() {
		rows.Scan(&id, &rollno, &name)
		fmt.Println(strconv.Itoa(id) + ": " + strconv.Itoa(rollno) + " " + name)
	}
}