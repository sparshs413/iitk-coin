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

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON", w)
		return
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
		models.SendResponse(400, "Please enter all the fields!", w)
		return 
	} else if (user.Rollno<170000 || user.Rollno>210000){
		models.SendResponse(403, "Roll number not authorized!", w)
		return 
	}

	query := database.InitalizeDatabase().QueryRow("select username from user where rollno=$1", user.Rollno)

	studentCheck := query.Scan(&user.Username)
	
	if studentCheck == nil {
		models.SendResponse(409, "User already exists!", w)
		return
    }

	hash := models.HashAndSalt([]byte(user.Password))
	status := models.AddUser(database.InitalizeDatabase(), user.Username, user.Name, user.Rollno, hash, user.Coins, user.PermissionsLevel, user.CompetitionsParticipated)

	if status {
		models.SendResponse(200, "User successfully created!", w)
	} else {
		models.SendResponse(500, "Error in creating user!", w)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	var user models.LoginCred
	json.Unmarshal([]byte(string(body)), &user)

	if err != nil {
		models.CheckErr(err)
		return
	}

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

				models.SendResponse(200, "Logged In Successfully!", w)
				return
			} else {
				models.SendResponse(400, "Passwords don't match!", w)
				return
			}
		}
	}

	models.SendResponse(404, "No such user present!", w)
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
			w.WriteHeader(http.StatusBadRequest)
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

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	var user models.UpdateCoins
	json.Unmarshal([]byte(string(body)), &user)

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		permission := models.GetUserPermission(database.InitalizeDatabase(), int(claims["rollno"].(float64)))

		if permission == 2 {
			userId := models.GetUserId(database.InitalizeDatabase(), user.Rollno)
			
			if userId == 0 {
				models.SendResponse(404, "No such user present!", w)		
				return
			}

			currentCoins := models.GetCoins(database.InitalizeDatabase(), user.Rollno)
			numCompetiton := models.GetNumCompetiton(database.InitalizeDatabase(), user.Rollno)		

			status := models.UpdateUser(database.InitalizeDatabase(), userId, user.Rollno, user.Coins+currentCoins)
			numCompetiton = numCompetiton + 1
			status2 := models.UpdateNumCompetitions(database.InitalizeDatabase(), userId, user.Rollno, numCompetiton)
			status3 := models.AddTransaction(database.InitalizeTransactionHistoryDatabase(), "add", user.Rollno, int(claims["rollno"].(float64)), user.Coins, time.Now().String())
		
			if status && status2 && status3 {
				models.SendResponse(200, "Coins given Successfully!", w)
			} else {
				models.SendResponse(500, "Error in giving coins, please try again!", w)
			}
		} else {
			models.SendResponse(401, "You are not authorized to give Coins!", w)
		}
	} else {
		models.SendResponse(500, "Please re-login and try again!", w)
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

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		if int(claims["rollno"].(float64)) != user.SenderRollno {
			models.SendResponse(401, "Please login from your own account!", w)
			return
		}
	} else {
		models.SendResponse(500, "Please try again!", w)
		return
	}

	senderUser := models.GetUserId(database.InitalizeDatabase(), user.SenderRollno)
	receiverUser := models.GetUserId(database.InitalizeDatabase(), user.ReceiverRollno)

	if senderUser == 0 {
		models.SendResponse(404, "No such sending user present!", w)
		return
	}

	if receiverUser == 0 {
		models.SendResponse(404, "No such receiving user present!", w)
		return
	}

	numCompetiton := models.GetNumCompetiton(database.InitalizeDatabase(), user.ReceiverRollno)	

	if numCompetiton == 0 {
		models.SendResponse(406, "User not eligible for getting coins!", w)
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
				
			models.SendResponse(200, "Coins Transferred Successfully!", w)	
			return
		} else {
			if status1 && !status2 {
				models.UpdateUser(database.InitalizeDatabase(), senderUser, user.SenderRollno, senderCoins+user.Coins)
				models.SendResponse(500, "Error in transferring coins, please try again!", w)		
				return
			} else if !status1 && status2 {
				models.UpdateUser(database.InitalizeDatabase(), senderUser, user.SenderRollno, receiverCoins-int(coins))
				models.SendResponse(500, "Error in transferring coins, please try again!", w)
				return
			} else {
				models.SendResponse(500, "Error in transferring coins, please try again!", w)
				return
			}
		}
	} else {
		models.SendResponse(409, "Insufficient Balance, to transfer!", w)
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

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	var user models.RetrieveBalance
	json.Unmarshal([]byte(string(body)), &user)

	userId := models.GetUserId(database.InitalizeDatabase(), user.Rollno)

	if userId == 0 {
		models.SendResponse(404, "No such user present!", w)
		return
	}

	response := models.RetrieveBalance {
		Rollno: user.Rollno,
		Coins: models.GetCoins(database.InitalizeDatabase(), user.Rollno),
	} 
	json.NewEncoder(w).Encode(response)
}

func Redeem(w http.ResponseWriter, r *http.Request){
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		panic(err)
	}

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	var redeem models.RedeemReqCust
	json.Unmarshal([]byte(string(body)), &redeem)

	if err != nil {
		models.CheckErr(err)
		return
	}

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		if int(claims["rollno"].(float64)) != redeem.Rollno {
			models.SendResponse(401, "Please login from your own account!", w)
			return
		}
	} else {
		models.SendResponse(500, "Please try again!", w)
		return
	}

	permission := models.GetUserPermission(database.InitalizeDatabase(), redeem.Rollno)

	if permission == 0 {
		currentBalance := models.GetCoins(database.InitalizeDatabase(), redeem.Rollno)

		if currentBalance < redeem.Coins {
			models.SendResponse(409, "Insufficient Balance, to redeem!", w)
			return
		} else {
			status := models.AddRedeemRequest(database.InitalizeDatabase(), redeem.ItemName, redeem.Rollno, redeem.Coins)

			if status {
				models.SendResponse(200, "Request Initiated!", w)
				return
			} else {
				models.SendResponse(500, "Error in creating request, please try again!", w)
				return
			}
		}		
	} else {
		models.SendResponse(406, "User is not eligible for redeeming!", w)
		return
	} 
}

func ApproveRequest(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if !models.IsJSON(string(body)) {
		models.SendResponse(400, "Invalid JSON!", w)
		return
	}

	var req models.AcceptReq
	json.Unmarshal([]byte(string(body)), &req)

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		permission := models.GetUserPermission(database.InitalizeDatabase(), int(claims["rollno"].(float64)))

		if permission == 2 {
			rollno, coins, status := models.GetReqData(database.InitalizeDatabase(), req.Id)

			rollno1, err1 := strconv.Atoi(rollno)
			coins1, err2 := strconv.Atoi(coins)
			status1, err3 := strconv.Atoi(status)

			if err1 == nil && err2 == nil && err3 == nil {
				if status1 != 1 {
					models.SendResponse(403, "Request already responded!", w)
					return
				}

				coins := models.GetCoins(database.InitalizeDatabase(), rollno1)
				if coins < coins1 {
					status := models.UpdateRequestStatus(database.InitalizeDatabase(), req.Id, 2)

					if status {
						models.SendResponse(200, "Request rejected, because of insufficient balance!", w)
						return
					} else {
						models.SendResponse(500, "Error in rejecting request, please try again!", w)
						return
					}
				} else {
					userId := models.GetUserId(database.InitalizeDatabase(), rollno1)
					status := models.UpdateUser(database.InitalizeDatabase(), userId, rollno1, coins-coins1)
					if status {
						status = models.UpdateRequestStatus(database.InitalizeDatabase(), req.Id, 0)
						if status {
							models.SendResponse(200, "Request accepted!", w)
							return
						} else {
							_ = models.UpdateUser(database.InitalizeDatabase(), userId, rollno1, coins+coins1)

							models.SendResponse(500, "Error in accepting request, please try again!", w)
							return
						}
					} else {
						models.SendResponse(500, "Error in accepting request, please try again!", w)
						return
					}
				}
			}
		} else {
			models.SendResponse(401, "You are not authorized to give Coins!", w)
			return
		}
	} else {
		models.SendResponse(500, "Please try again!", w)
		return
	}
}

func ShowUnapprovedRequest(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json") 

	claims, status1 := models.ExtractClaims(r.Header["Token"][0])

	if status1 {
		permission := models.GetUserPermission(database.InitalizeDatabase(), int(claims["rollno"].(float64)))

		if permission == 2 {
			rows2, _ := database.InitalizeDatabase().Query("SELECT id, rollno, coins, itemName, status FROM redeem")

			var id2 int
			var rollno1 string
			var coins1 string
			var status string
			var itemName string
		
			for rows2.Next() {
				rows2.Scan(&id2, &rollno1, &coins1, &itemName, &status)
				if status == "1" {
					fmt.Println(strconv.Itoa(id2) + ": " + rollno1 + " " + coins1 + " " + itemName + " " + status)
				}
			}
		} else {
			models.SendResponse(401, "You are not authorized to view unapproved requests!", w) 
			return
		}
	} else {
		models.SendResponse(500, "Please try again!", w)
		return
	}
}
