package controllers

import (
	"encoding/json"
	"fmt"
	"iitk-coin/models"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"iitk-coin/database"

	"iitk-coin/auth"

	"github.com/dgrijalva/jwt-go"
)

var lock sync.Mutex

func Signup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var user models.User
	json.Unmarshal([]byte(string(body)), &user)

	user.Coins = 0
	user.PermissionsLevel = 0
	user.CompetitionsParticipated = 0
	if user.Rollno == 999999 {
		user.PermissionsLevel = 2
	}
	

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
	status := models.AddUser(database.InitalizeDatabase(), user.Username, user.Name, user.Rollno, hash, user.Coins, user.PermissionsLevel, user.CompetitionsParticipated)

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
			// fmt.Println(r.Header["Token"][0])
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
			w.WriteHeader(http.StatusInternalServerError)
			response := models.Response {
				Message: "No Authorization Token provided!",
			} 
			json.NewEncoder(w).Encode(response)
		}
	})
}

func SecretPage(w http.ResponseWriter, r *http.Request) {
	response := models.Response {
		Message: "Secret Info for User!",
	} 
	json.NewEncoder(w).Encode(response)
}

func GiveCoins(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user models.UpdateCoins
	json.Unmarshal([]byte(string(body)), &user)

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		permission := models.GetUserPermission(database.InitalizeDatabase(), int(claims["rollno"].(float64)))

		if permission == 2 {
			userId := models.GetUserId(database.InitalizeDatabase(), user.Rollno)
			
			if userId == 0 {
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "No such user present!",
				} 
				json.NewEncoder(w).Encode(response) 
		
				return
			}

			currentCoins := models.GetCoins(database.InitalizeDatabase(), user.Rollno)
			numCompetiton := models.GetNumCompetiton(database.InitalizeDatabase(), user.Rollno)		

			status := models.UpdateUser(database.InitalizeDatabase(), userId, user.Rollno, user.Coins+currentCoins)
			numCompetiton = numCompetiton + 1
			status2 := models.UpdateNumCompetitions(database.InitalizeDatabase(), userId, user.Rollno, numCompetiton)
			status3 := models.AddTransaction(database.InitalizeTransactionHistoryDatabase(), "add", user.Rollno, int(claims["rollno"].(float64)), user.Coins, time.Now().String())
		
			if status && status2 && status3 {
				response := models.Response {
					Message: "Coins given Successfully!",
				} 
				json.NewEncoder(w).Encode(response) 
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "Error in giving coins, please try again!",
				} 
				json.NewEncoder(w).Encode(response) 
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			response := models.Response {
				Message: "You are not authorized to give Coins!",
			} 
			json.NewEncoder(w).Encode(response) 
		}
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "Please re-login and try again!",
		} 
		json.NewEncoder(w).Encode(response) 
	}
}	

func TransferCoins(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user models.TransferCoins
	json.Unmarshal([]byte(string(body)), &user)

	senderUser := models.GetUserId(database.InitalizeDatabase(), user.SenderRollno)
	receiverUser := models.GetUserId(database.InitalizeDatabase(), user.ReceiverRollno)

	if senderUser == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "No such sending user present!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
	}

	if receiverUser == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "No such receiving user present!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
	}

	numCompetiton := models.GetNumCompetiton(database.InitalizeDatabase(), user.ReceiverRollno)	
	if numCompetiton == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "User not eligible for getting coins!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
	}

	senderCoins := models.GetCoins(database.InitalizeDatabase(), user.SenderRollno)
	receiverCoins := models.GetCoins(database.InitalizeDatabase(), user.ReceiverRollno)

	if senderCoins >= user.Coins {
		var coins float64 = float64(user.Coins)
		diff := user.SenderRollno/10000 - user.ReceiverRollno/10000

		if math.Abs(float64(diff)) > 0 {
			coins = (coins*2)/3
		} else if math.Abs(float64(diff)) == 0 {
			coins = (coins*49)/50
		}

		status1 := models.UpdateUser(database.InitalizeDatabase(), senderUser, user.SenderRollno, senderCoins-user.Coins)
		status2 := models.UpdateUser(database.InitalizeDatabase(), receiverUser, user.ReceiverRollno, receiverCoins+int(coins))

		if status1 && status2 {
			models.AddTransaction(database.InitalizeTransactionHistoryDatabase(), "transfer", user.ReceiverRollno, user.SenderRollno, user.Coins, time.Now().String())
				
			response := models.Response {
				Message: "Coins Transferred Successfully!",
			} 
			json.NewEncoder(w).Encode(response) 
	
			return
		} else {
			if status1 && !status2 {
				models.UpdateUser(database.InitalizeDatabase(), senderUser, user.SenderRollno, senderCoins+user.Coins)
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "Error in transferring coins, please try again!",
				} 
				json.NewEncoder(w).Encode(response) 
		
				return
			} else if !status1 && status2 {
				models.UpdateUser(database.InitalizeDatabase(), senderUser, user.SenderRollno, receiverCoins-int(coins))
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "Error in transferring coins, please try again!",
				} 
				json.NewEncoder(w).Encode(response) 
		
				return
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				response := models.Response {
					Message: "Error in transferring coins, please try again!",
				} 
				json.NewEncoder(w).Encode(response) 
		
				return
			}
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		response := models.Response {
			Message: "Insufficient Balance, to transfer!",
		} 
		json.NewEncoder(w).Encode(response) 

		return
	}
}

func Balance(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(time.Millisecond)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user models.RetrieveBalance
	json.Unmarshal([]byte(string(body)), &user)

	userId := models.GetUserId(database.InitalizeDatabase(), user.Rollno)

	if userId == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		response := models.Response {
			Message: "No such user present!",
	    } 
		json.NewEncoder(w).Encode(response) 

		return
	}

	response := models.RetrieveBalance {
		Rollno: user.Rollno,
		Coins: models.GetCoins(database.InitalizeDatabase(), user.Rollno),
	} 
	json.NewEncoder(w).Encode(response)
}