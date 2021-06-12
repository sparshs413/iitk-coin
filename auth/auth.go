package auth

import (
	"fmt"
	"time"

	"iitk-coin/models"

	"github.com/dgrijalva/jwt-go"
)

func GetJWT(username string, rollno int, name string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["rollno"] = rollno
	claims["name"] = name
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()

	tokenString, err := token.SignedString(models.MySigningKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}
