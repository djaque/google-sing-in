package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/tkanos/gonfig"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Setup which stores google ids and urls, scopes, and blablabla
type Setup struct {
	// Keep the vars defined on file at the beginning
	Scopes      []string `json:"scopes" env:"SCOPES"`
	UserURI     string   `json:"userinfo_uri" env:"USERINFO_URI"`
	// Keep the vars defined by environment at the end of this struct
	Cid         string   `json:"client_id" env:"CLIENT_ID"`
	Csecret     string   `json:"client_secret" env:"CLIENT_SECRET"`
	RedirectURL string   `json:"redirect_url" env:"REDIRECT_URL"`
}

// User is a retrieved and authentiacted user.
type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

var setup Setup
var conf *oauth2.Config
var state string
var store = sessions.NewCookieStore([]byte("secret"))

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func init() {
	err := gonfig.GetConf("./config.json", &setup)
	if err != nil {
		log.Printf("i cant load config: %v\n", err)
		os.Exit(1)
	}
	log.Printf("Json: %+v\n", setup)

	conf = &oauth2.Config{
		ClientID:     setup.Cid,
		ClientSecret: setup.Csecret,
		RedirectURL:  setup.RedirectURL,
		// You have to select your own scope from
		// here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		Scopes:   setup.Scopes,
		Endpoint: google.Endpoint,
	}
}

func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"title": "Login con Google",
	})
}

func getLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func authHandler(c *gin.Context) {
	// Handle the exchange code to initiate a transport.
	session := sessions.Default(c)
	retrievedState := session.Get("state")
	if retrievedState != c.Query("state") {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
		return
	}

	tok, err := conf.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	client := conf.Client(oauth2.NoContext, tok)
	email, err := client.Get(setup.UserURI)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	defer email.Body.Close()
	data, _ := ioutil.ReadAll(email.Body)
	log.Printf("DATA:%s\n", string(data))
	user := User{}
	if err := json.Unmarshal(data, &user); err != nil {
		panic(err)
	}

	log.Printf("Email body:  %+v\n", user)
	c.HTML(http.StatusOK, "success.html", gin.H{
		"title":   "Logged with Google",
		"email":   user.Email,
		"picture": user.Picture,
	})
}

func loginHandler(c *gin.Context) {
	state = randToken()
	session := sessions.Default(c)
	session.Set("state", state)
	session.Save()
	c.Writer.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + getLoginURL(state) + "'><button>Login with Google!</button> </a> </body></html>"))
}

func main() {
	router := gin.Default()
	router.Use(sessions.Sessions("goquestsession", store))
	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/login", loginHandler)
	router.GET("/auth", authHandler)

	router.Run("127.0.0.1:9090")
}
