package main

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	// First we create our oauth2 struct
	githubOauthConfig = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     github.Endpoint,
		RedirectURL:  "http://localhost:8080/oauth2/receive",
	}
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

}
