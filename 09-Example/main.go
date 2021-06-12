package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	password []byte
	First    string
}

type customClaims struct {
	jwt.StandardClaims
	SID string
}

var (
	// key is email, value is user
	db = map[string]user{}
	// key is sessionid, value is email
	sessions = map[string]string{}
	key      = []byte("mySecretKey")
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)
}

func logout(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	// remove the session
	delete(sessions, sID)

	// remove cookie
	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var email string
	if sID != "" {
		email = sessions[sID]
	}

	var first string
	if user, ok := db[email]; ok {
		first = user.First
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
		<p>IF YOU HAVE A SESSION, HERE IS YOUN NAME: %s</p>
		<p>IF YOU HAVE A SESSION, HERE IT IS: %s</p>
		<p>IF THERE IS A MESSAGE FOR YOU, HERE IT IS: %s</p>
		<p>REGISTER</p>
		<form action="/submit" method="POST">
			<label for="first">First</label>
			<input type="text" name="first" placeholder="First"/>
			<label for="email">Email</label>
			<input type="email" name="email" placeholder="Email"/>
			<label for="password">Password</label>
			<input type="password" name="password" placeholder="Password"/>
			<input type="submit"/>
		</form>
		<p>LOG IN</p>
		<form action="/login" method="POST">
			<label for="email">Email</label>
			<input type="email" name="email" placeholder="Email"/>
			<label for="password">Password</label>
			<input type="password" name="password" placeholder="Password"/>
			<input type="submit"/>
		</form>
		<p>LOG OUT</p>
		<form action="/logout" method="POST">
			<input type="submit" value="Logout"/>
		</form>
	</body>
	</html>`, first, email, msg)
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

	f := r.FormValue("first")
	if f == "" {
		msg := url.QueryEscape("your first name needs not to be empty")
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
	db[email] = user{
		password: bs,
		First:    f,
	}

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

	if err := bcrypt.CompareHashAndPassword(db[email].password, []byte(pwd)); err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	sUUID := uuid.New().String()
	sessions[sUUID] = email
	token, err := createToken(sUUID)
	if err != nil {
		log.Println("couldn't createToken in login", err)
		msg := url.QueryEscape("try again later")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}

	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + email)
	http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
}

func createToken(sid string) (string, error) {
	cc := customClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("couldn't sign token in createToken %w", err)
	}

	return st, nil

	// mac := hmac.New(sha256.New, key)
	// mac.Write([]byte(sid))

	// // to hex
	// // signedMac := fmt.Sprintf("%x", mac.Sum(nil))

	// // to base64
	// signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// return signedMac + "|" + sid
}

func parseToken(st string) (string, error) {
	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		// checks the encoding algorithm of the signed token
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return key, nil
	})

	if err != nil {
		return "", fmt.Errorf("couldn't parseTokenWithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseTokenWithClaims")
	}

	return token.Claims.(*customClaims).SID, nil

	// xs := strings.SplitN(st, "|", 2)
	// if len(xs) != 2 {
	// 	return "", fmt.Errorf("stop hacking me")
	// }

	// xb, err := base64.StdEncoding.DecodeString(xs[0])
	// if err != nil {
	// 	return "", fmt.Errorf("couldn't parseToken decodestring %w", err)
	// }

	// mac := hmac.New(sha256.New, key)
	// mac.Write([]byte(xs[1]))

	// if !hmac.Equal(xb, mac.Sum(nil)) {
	// 	return "", fmt.Errorf("couldn't parseToken not equal signed and sid")
	// }

	// return xs[1], nil
}
