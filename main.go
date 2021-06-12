package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"iitk-coin/controllers"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"iitk-coin/database"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var mySigningKey = []byte("pingala")  // Can be taken from a .env file

type User struct {
	Username string `json:"username"` 
	Rollno  int  `json:"rollno"`
	Name string  `json:"name"` 
	Password string `json:"password"` 
}

type LoginCred struct {
	Rollno int `json:"rollno"`
	Password string `json:"password"`
}

type App struct {
	DB *sql.DB
}

type Response struct { 
	Message string `json:"message"` 
}
		
var a = &App{}

func GetJWT(username string, rollno int, name string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["rollno"] = rollno
	claims["name"] = name
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func addUser(db *sql.DB, username string, name string, rollno int, password string) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO user (username, name, rollno, password) VALUES (?, ?, ?, ?)")
	_, err := stmt.Exec(username, name, rollno, password)
	if err != nil {
		checkErr(err)
		return false
	}
	tx.Commit()

	return true
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}
	
	return true
}

func signup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
			panic(err)
	}
	var user User
	json.Unmarshal([]byte(string(body)), &user)

	if (user.Username == "" || user.Password == "" || user.Name == "") {
		w.WriteHeader(http.StatusInternalServerError)
		response := Response {
			Message: "Please enter all the fields!",
	    } 
		json.NewEncoder(w).Encode(response)
		return 
	} else if (user.Rollno<170000 || user.Rollno>210000){
		w.WriteHeader(http.StatusInternalServerError)
		response := Response {
			Message: "Roll number not authorized!",
	    } 
		json.NewEncoder(w).Encode(response)
		return 
	}

	query := a.DB.QueryRow("select username from user where rollno=$1", user.Rollno)

	studentCheck := query.Scan(&user.Username)
	
	if studentCheck == nil {
		w.WriteHeader(http.StatusUnauthorized)
		response := Response {
			Message: "User already exists!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
    }

	hash := hashAndSalt([]byte(user.Password))
	status := addUser(a.DB, user.Username, user.Name, user.Rollno, hash)

	if status {
		response := Response {
			Message: "User successfully created!",
	    } 
		json.NewEncoder(w).Encode(response) 
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		response := Response {
			Message: "Error in creating user!",
	    } 
		json.NewEncoder(w).Encode(response) 
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user LoginCred
	json.Unmarshal([]byte(string(body)), &user)

	if err != nil {
		checkErr(err)
		return
	}

	// query := a.DB.QueryRow("select password from user where rollno=$1", user.Rollno)
	// fmt.Println(query)

	// hashPassword := hashAndSalt([]byte(user.Password))

	// err = query.Scan(&hashPassword)
	// fmt.Println(err == sql.ErrNoRows)

	// if err != nil {
	// 	if err == sql.ErrNoRows {
			// w.WriteHeader(http.StatusUnauthorized)
			// response := Response {
			// 	Message: "No such user present!",
			// } 
			// json.NewEncoder(w).Encode(response) 
			// return
	// 	}
	// 	// If the error is of any other type, send a 500 status
		// w.WriteHeader(http.StatusInternalServerError)
		// response := Response {
		// 	Message: "Passwords don't match!",
	    // } 
		// json.NewEncoder(w).Encode(response) 
	// 	return
	// } else {
	// 	pwd_matches := comparePasswords(password, []byte(user.Password))
	// 	response := Response {
	// 		Message: "Logged In Successfully!",
	//     } 
	// 	json.NewEncoder(w).Encode(response) 
	// }

	rows, _ := a.DB.Query("SELECT id, username, name, rollno, password FROM user")

	var id int
	var username string
	var name string
	var rollno string
	var password string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password)
		rollnos, _ := strconv.Atoi(rollno)
		if rollnos == user.Rollno {
			pwd_matches := comparePasswords(password, []byte(user.Password))
			
			if pwd_matches {
				validToken, err := GetJWT(username, rollnos, name)

				fmt.Println(validToken)

				if err != nil {
					fmt.Println("Failed to generate token")
					return
				}

				response := Response {
					Message: "Logged In Successfully!",
				} 
				json.NewEncoder(w).Encode(response) 

				return
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				response := Response {
					Message: "Passwords don't match!",
				} 
				json.NewEncoder(w).Encode(response) 
			}
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	response := Response {
		Message: "No such user present!",
	} 
	json.NewEncoder(w).Encode(response) 
}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			fmt.Println(r.Header["Token"][0])
			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					w.WriteHeader(http.StatusUnauthorized)
					response := Response {
						Message: "Invalid Signing Method!",
					} 
					json.NewEncoder(w).Encode(response) 
					return nil, json.NewEncoder(w).Encode(response)
				}
				if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
					w.WriteHeader(http.StatusUnauthorized)
					response := Response {
						Message: "Expired token!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
				aud := "billing.jwtgo.io"
				checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !checkAudience {
					w.WriteHeader(http.StatusUnauthorized)
					response := Response {
						Message: "invalid aud!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
				iss := "jwtgo.io"
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					w.WriteHeader(http.StatusUnauthorized)
					response := Response {
						Message: "invalid iss!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
			
				return mySigningKey, nil
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
					response := Response {
						Message: err.Error(),
					} 
					json.NewEncoder(w).Encode(response)
			}
			
			if token.Valid {
				endpoint(w, r)
			}
		} else {
			fmt.Fprintf(w, "No Authorization Token provided")
		}
	})
}

func secretPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, `{"response": "Secret Info for User!"}`)
}

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
