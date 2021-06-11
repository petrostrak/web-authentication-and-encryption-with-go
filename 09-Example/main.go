package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	db       = map[string][]byte{}
	key      = []byte("mySecretKey")
	sessions = map[string]string{}
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	s, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var email string
	if s != "" {
		email = sessions[s]
	}

	msg := r.FormValue("errormsg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Hands on exercises</title>
	</head>
	<body>
		<p>IF YOU HAVE A SESSION, HERE IT IS: %s</p>
		<p>IF THERE IS A MESSAGE FOR YOU, HERE IT IS: %s</p>
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
	</html>`, email, msg)
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

	sUUID := uuid.New().String()
	sessions[sUUID] = email
	token := createToken(sUUID)

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}

	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + email)
	http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
}

func createToken(sid string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sid))

	// to hex
	// signedMac := fmt.Sprintf("%x", mac.Sum(nil))

	// to base64
	signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return signedMac + "|" + sid
}

func parseToken(ss string) (string, error) {
	xs := strings.SplitN(ss, "|", 2)
	if len(xs) != 2 {
		return "", fmt.Errorf("stop hacking me")
	}

	xb, err := base64.StdEncoding.DecodeString(xs[0])
	if err != nil {
		return "", fmt.Errorf("couldn't parseToken decodestring %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(xs[1]))

	if !hmac.Equal(xb, mac.Sum(nil)) {
		return "", fmt.Errorf("couldn't parseToken not equal signed and sid")
	}

	return xs[1], nil
}
