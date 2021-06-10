package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

var (
	db = map[string][]byte{}
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {

	errMsg := r.FormValue("errormsg")

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Hands on exercises</title>
	</head>
	<body>
		<p>IF THERE WAS AN ERROR, HERE IT IS: ` + errMsg + `</p>
		<form action="/submit" method="POST">
			<p>Email</p>
			<input type="email" name="email"/>
			<p>Password</p>
			<input type="password" name="password"/>
			<input type="submit"/>
		</form>
	</body>
	</html>`

	io.WriteString(w, html)
}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		errMsg := url.QueryEscape("your methor was not post")
		http.Redirect(w, r, "/?errormsg="+errMsg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		errMsg := url.QueryEscape("your email needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+errMsg, http.StatusSeeOther)
		return
	}
	pwd := r.FormValue("password")
	if pwd == "" {
		errMsg := url.QueryEscape("your password needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+errMsg, http.StatusSeeOther)
		return
	}

	bs, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "there was an internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Println(email)
	fmt.Println(bs)
	db[email] = bs

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
