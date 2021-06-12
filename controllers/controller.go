package controllers

import (
	"encoding/json"
	"fmt"
	"iitk-coin/models"
	"io/ioutil"
	"net/http"
	"strconv"

	"iitk-coin/database"

	"iitk-coin/auth"

	"github.com/dgrijalva/jwt-go"
)

func Signup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
			panic(err)
	}
	var user models.User
	json.Unmarshal([]byte(string(body)), &user)

	if (user.Username == "" || user.Password == "" || user.Name == "") {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "Please enter all the fields!",
	    } 
		json.NewEncoder(w).Encode(response)
		return 
	} else if (user.Rollno<170000 || user.Rollno>210000){
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "Roll number not authorized!",
	    } 
		json.NewEncoder(w).Encode(response)
		return 
	}

	query := database.InitalizeDatabase().QueryRow("select username from user where rollno=$1", user.Rollno)

	studentCheck := query.Scan(&user.Username)
	
	if studentCheck == nil {
		w.WriteHeader(http.StatusUnauthorized)
		response := models.Response {
			Message: "User already exists!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
    }

	hash := models.HashAndSalt([]byte(user.Password))
	status := models.AddUser(database.InitalizeDatabase(), user.Username, user.Name, user.Rollno, hash)

	if status {
		response := models.Response {
			Message: "User successfully created!",
	    } 
		json.NewEncoder(w).Encode(response) 
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "Error in creating user!",
	    } 
		json.NewEncoder(w).Encode(response) 
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user models.LoginCred
	json.Unmarshal([]byte(string(body)), &user)

	if err != nil {
		models.CheckErr(err)
		return
	}

	// query := database.InitalizeDatabase().QueryRow("select password from user where rollno=$1", user.Rollno)
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

	rows, _ := database.InitalizeDatabase().Query("SELECT id, username, name, rollno, password FROM user")

	var id int
	var username string
	var name string
	var rollno string
	var password string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password)
		rollnos, _ := strconv.Atoi(rollno)
		if rollnos == user.Rollno {
			pwd_matches := models.ComparePasswords(password, []byte(user.Password))
			
			if pwd_matches {
				validToken, err := auth.GetJWT(username, rollnos, name)

				fmt.Println(validToken)

				if err != nil {
					fmt.Println("Failed to generate token")
					return
				}

				response := models.Response {
					Message: "Logged In Successfully!",
				} 
				json.NewEncoder(w).Encode(response) 

				return
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "Passwords don't match!",
				} 
				json.NewEncoder(w).Encode(response) 
				return
			}
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	response := models.Response {
		Message: "No such user present!",
	} 
	json.NewEncoder(w).Encode(response) 
}

func IsAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			fmt.Println(r.Header["Token"][0])
			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					w.WriteHeader(http.StatusUnauthorized)
					response := models.Response {
						Message: "Invalid Signing Method!",
					} 
					json.NewEncoder(w).Encode(response) 
					return nil, json.NewEncoder(w).Encode(response)
				}
				if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
					w.WriteHeader(http.StatusUnauthorized)
					response := models.Response {
						Message: "Expired token!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
				aud := "billing.jwtgo.io"
				checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !checkAudience {
					w.WriteHeader(http.StatusUnauthorized)
					response := models.Response {
						Message: "invalid aud!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
				iss := "jwtgo.io"
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					w.WriteHeader(http.StatusUnauthorized)
					response := models.Response {
						Message: "invalid iss!",
					} 
					
					return nil, json.NewEncoder(w).Encode(response)
				}
			
				return models.MySigningKey, nil
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
					response := models.Response {
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

func SecretPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, `{"response": "Secret Info for User!"}`)
}