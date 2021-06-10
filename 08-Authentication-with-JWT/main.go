package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type myClaims struct {
	jwt.StandardClaims
	Email string
}

const (
	myKey = "ilovethursdayswhenitrains2much"
)

func main() {
	http.HandleFunc("/", foo)
	http.HandleFunc("/submit", bar)
	http.ListenAndServe(":8080", nil)
}

func getJWT(msg string) (string, error) {
	claims := myClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	ss, err := token.SignedString([]byte(myKey))
	if err != nil {
		return "", fmt.Errorf("couldn't signedString in getJWT in NewWithClaims %w", err)
	}

	return ss, nil
}

func bar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ss, err := getJWT(email)
	if err != nil {
		http.Error(w, "couldn't getJWT", http.StatusInternalServerError)
		return
	}

	c := http.Cookie{
		Name:  "session",
		Value: ss,
	}

	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func foo(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	ss := c.Value
	afterVerT, err := jwt.ParseWithClaims(ss, &myClaims{}, func(beforeVerT *jwt.Token) (interface{}, error) {
		return []byte(myKey), nil
	})

	// StandardClaims has the Valid() method which means it implements the Claims interface
	// Where we ParseClaims as with "ParseWithClaims", the Valid() method gets run and if all
	// is well, then returns no "error" and type TOKEN which has a field VALID will be true.

	// First we check if there is an error and then we validate the token. The opposite would
	// cause an error "cannot dereference from nil" because ParseWithClaims might return nil.
	isEqual := err == nil && afterVerT.Valid

	message := "Not logged in"
	if isEqual {
		message = "Logged in"
		claims := afterVerT.Claims.(*myClaims)
		fmt.Println(claims.Email)
		fmt.Println(claims.ExpiresAt)
	}

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Example</title>
	</head>
	<body>
		<p>Cookie Value: ` + c.Value + `</p>
		<p>Status: ` + message + `</p>
		<form action="/submit" method="post">
			<input type="email" name="email"/>
			<input type="submit"/>
		</form>
	</body>
	</html>`

	io.WriteString(w, html)
}
