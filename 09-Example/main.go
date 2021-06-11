package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {

	msg := r.FormValue("errormsg")

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Hands on exercises</title>
	</head>
	<body>
		<p>IF THERE WAS AN ERROR, HERE IT IS: ` + msg + `</p>
		<p>REGISTER</p>
		<form action="/submit" method="POST">
			<p>Email</p>
			<input type="email" name="email"/>
			<p>Password</p>
			<input type="password" name="password"/>
			<input type="submit"/>
		</form>
		<p>LOG IN</p>
		<form action="/login" method="POST">
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
		msg := url.QueryEscape("your methor was not post")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		msg := url.QueryEscape("your email needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}
	pwd := r.FormValue("password")
	if pwd == "" {
		msg := url.QueryEscape("your password needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
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

func login(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your methor was not post")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		msg := url.QueryEscape("your email needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}
	pwd := r.FormValue("password")
	if pwd == "" {
		msg := url.QueryEscape("your password needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[email]; !ok {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	if err := bcrypt.CompareHashAndPassword(db[email], []byte(pwd)); err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + email)
	http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
}

func createToken(sid string) string {
	key := []byte("mySecretKey")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sid))

	// to hex
	// signedMac := fmt.Sprintf("%x", mac.Sum(nil))

	// to base64
	signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return signedMac + "|" + sid
}
