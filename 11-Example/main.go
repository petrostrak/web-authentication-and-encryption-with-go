package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

type user struct {
	password []byte
	First    string
}

type customClaims struct {
	jwt.StandardClaims
	SID string
}

type amazonResponse struct {
	Email  string `json:"email"`
	Name   string `json:"name"`
	UserID string `json:"user_id"`
}

var (
	// key is email, value is user
	db = map[string]user{}
	// key is sessionid, value is email
	sessions = map[string]string{}
	// key is uuid from oauth login, value is expiretion time
	oauthExp = map[string]time.Time{}
	// key is amazonID, value is email
	amazonConnetions = map[string]string{}
	key              = []byte("mySecretKey")
	oauth            = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     amazon.Endpoint,
		RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
		Scopes:       []string{"profile"},
	}
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/oauth/amazon/login", oAmazonLogin)
	// This is our redirectURL "http://localhost:8080/oauth/amazon/receive"
	http.HandleFunc("/oauth/amazon/receive", oAmazonReceive)
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("//oauth/amazon/register", amazonRegister)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)
}

func amazonRegister(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your methor was not post")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("first")
	if f == "" {
		msg := url.QueryEscape("your first name needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		msg := url.QueryEscape("your email needs not to be empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	oauthID := r.FormValue("oauthID")
	if oauthID == "" {
		msg := url.QueryEscape("oauthID came through as empty")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	amazonUserID, err := parseToken(oauthID)
	if err != nil {
		log.Println("parseToken in oAmazonRegister didn't parse")
		msg := url.QueryEscape("there was an issue")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	db[email] = user{
		First: f,
	}

	amazonConnetions[amazonUserID] = email

	if err := createSession(email, w); err != nil {
		log.Println("couldn't createSession in amazonRegister")
		msg := url.QueryEscape("there was an issue")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	sst := r.FormValue("signendToken")
	name := r.FormValue("name")
	email := r.FormValue("email")

	if sst != "" {
		log.Println("couldn't get signed token")
		msg := url.QueryEscape("try again later")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Hands on exercises</title>
	</head>
	<body>
		<p>REGISTER</p>
		<form action="/oauth/amazon/register" method="POST">
			<label for="first">First</label>
			<input type="text" name="first" placeholder="First" value="%s"/>
			<label for="email">Email</label>
			<input type="email" name="email" placeholder="Email" value="%s"/>
			<input type="hidden" name="oauthID" value="%s"/>
			<input type="submit"/>
		</form>
	</body>
	</html>`, name, email, sst)
}

func oAmazonReceive(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		msg := url.QueryEscape("state was empty in oAmazonReceive")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("code was empty in oAmazonReceive")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	expT := oauthExp[state]
	if time.Now().After(expT) {
		msg := url.QueryEscape("oauth took too long time.now.after")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	// Exchange our code for a token. This uses the client secret also
	// The TokenURL is called and we get back a token
	t, err := oauth.Exchange(r.Context(), code)
	if err != nil {
		msg := url.QueryEscape("couldn't do oauth exchange " + err.Error())
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	tokenSource := oauth.TokenSource(r.Context(), t)
	client := oauth2.NewClient(r.Context(), tokenSource)

	resp, err := client.Get("https://amazon.com/user/profile")
	if err != nil {
		http.Error(w, "couldn't get profile", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		http.Error(w, "not a 200 resp status code", http.StatusInternalServerError)
		return
	}

	// fmt.Println(resp)
	// bs, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	http.Error(w, "couldn't read amazon info", http.StatusInternalServerError)
	// 	return
	// }

	var ar amazonResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		http.Error(w, "amazon invalid response", http.StatusSeeOther)
		return
	}

	email, ok := amazonConnetions[ar.UserID]
	if !ok {
		// Register at our site with amazon
		signendToken, err := createToken(ar.UserID)
		if err != nil {
			log.Println("couldn't createToken in oAmazonReceive", err)
			msg := url.QueryEscape("try again later")
			http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
			return
		}

		uv := url.Values{}
		uv.Add("sst", signendToken)
		uv.Add("name", ar.Name)
		uv.Add("email", ar.Email)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
		return
	}

	if err := createSession(email, w); err != nil {
		log.Println("couldn't createSession in oAmazonReceive", err)
		msg := url.QueryEscape("try again later")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + email)
	http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
}

func oAmazonLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	id := uuid.New().String()
	oauthExp[id] = time.Now().Add(time.Hour)

	// oauth.AuthCodeURL besides the uuid that we create and pass in, it includes our ClientID. So
	// amazon in this case knows how is making the request.
	// This Redirect, goes from our site, to amazons and more specifically, to "https://www.amazon.com/ap/oa"
	// which is declared in Endpoint.AuthURL
	http.Redirect(w, r, oauth.AuthCodeURL(id), http.StatusSeeOther)
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
		<p>LOG IN WITH AMAZON</p>
		<form action="/oauth/amazon/login" method="POST">
			<input type="submit" value="LOGIN WITH AMAZON"/>
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

	if err := createSession(email, w); err != nil {
		log.Println("couldn't createToken in login", err)
		msg := url.QueryEscape("try again later")
		http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + email)
	http.Redirect(w, r, "/?errormsg="+msg, http.StatusSeeOther)
}

func createSession(email string, w http.ResponseWriter) error {
	sUUID := uuid.New().String()
	sessions[sUUID] = email
	token, err := createToken(sUUID)
	if err != nil {
		return fmt.Errorf("couldn't create token: %w", err)
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
		Path:  "/",
	}

	http.SetCookie(w, &c)

	return nil
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
