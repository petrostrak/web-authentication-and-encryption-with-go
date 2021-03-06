package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// JSON layout {"data":{"viewer":{"id":"SomeStringID..."}}}
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

var (
	// First we create our oauth2 struct
	githubOauthConfig = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     github.Endpoint,
		RedirectURL:  "http://localhost:8080/oauth2/receive",
	}

	// Key is githubID, value is user ID
	githubConnections map[string]string
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth/receive", completeGithubOauth)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Hands on exercises</title>
	</head>
	<body>
		<form action="/oauth/github" method="post">
			<input type="submit" value="Login with Github"/>
		</form>
	</body>
	</html>`)
}

// startGithubOauth starts the oauth2 process
//
// This will redirect to github and will redirect to localhost:8080/oauth2/receive
// with a code query and a state. The code query is needed from the server to create
// the token. The state is a token to protect the user from CSRF attacks and is passed
// in githubOauthConfig.AuthCodeURL("0000")
func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state != "0000" {
		http.Error(w, "state is incorrect", http.StatusBadRequest)
		return
	}

	// Exchange returns a token from the code query received from github.
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "couldn't login", http.StatusInternalServerError)
		return
	}

	// TokenSource receives the created token and creates the token source.
	tokenSource := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), tokenSource)

	// We make a post request to GraphQL with the following request body,
	// we are looking for the viewers id
	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "couldn't read github info", http.StatusInternalServerError)
		return
	}

	// Github response with:
	// {"data":{"viewer":{"id":"SomeStringID..."}}}
	// At this point, we need to unmarshal this json.
	log.Println(string(bs))

	var gr githubResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		http.Error(w, "github invalid response", http.StatusInternalServerError)
		return
	}

	// After we decode our id, we would need to store it in DB
	githubID := gr.Data.Viewer.ID
	userID, ok := githubConnections[githubID]
	if !ok {
		// New User, create account
	}

	// Login to account userID using JWT
	fmt.Println(userID)
}
