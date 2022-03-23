package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func getEnvVariable(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv(key)
}

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/redirect",
		ClientID:     getEnvVariable("Google_Client_Id"),
		ClientSecret: getEnvVariable("Google_Client_Secret"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
)

func Home(w http.ResponseWriter, r *http.Request) {
	var html = `<html><body><a href="\login">Google Log In</a></body></html>`
	fmt.Fprint(w, html)
}

func Login(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("randomize")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func Redirect(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != "randomize" {
		fmt.Println("State is not valid")
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
		return
	}
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		fmt.Printf("Could not get token: %s \n", err.Error())
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
		return
	}
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Printf("Could not send request: %s \n", err.Error())
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Could not parse request: %s \n", err.Error())
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
		return
	}
	fmt.Fprintf(w, "Response: %s", content)
}
func main() {
	http.HandleFunc("/home", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/redirect", Redirect)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
