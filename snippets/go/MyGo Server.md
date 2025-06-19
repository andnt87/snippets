# MyGo Server

- Directory: go
- File: MyGo Server

## Templates

### request url get parameter

```go
// ?token=
r.URL.Query().Get("token"),

```

### request get form value

```go
email := r.FormValue("email")
```

### writer header etag

```go
// Generate ETag for dynamic content
etag := generateETag(content)
w.Header().Set("ETag", etag)

// Compare with the ETag in the request
if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
    w.WriteHeader(http.StatusNotModified)
    return
}
```

### request method post (not allow if not post)

```go
if r.Method != http.MethodPost {
    w.Header().Set("Allow", "POST")
    http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    return

}
```

### request get url parametr as integer

```go
parse url parameter as int (/ciao?id=1)
```

### request base url path

```go
//   / 			 => /
//   /ciao 		 => ciao
//   /ciao/Andrei   => Andrei
local := path.Base(r.URL.Path)
```

### request isAuth (is authenticated)

```go
user, ok := r.Context().Value("auth").(User)
if !ok || !user.IsAuth {
    setFlash(w, flashCookie, "Please login")
    http.Redirect(w, r, "/login", http.StatusSeeOther)
    return
}
```

### writer header no cahce

```go
w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
w.Header().Set("Pragma", "no-cache")
w.Header().Set("Expires", "0")
```

### writer header set html

```go
w.Header().Set("Content-Type", "text/html")
```

### writer header set redirect

```go
w.Header().Set("Location", "http://google.com")
w.WriteHeader(302)
```

### writer serve favicon

```go
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/favicon.ico")
}
```

### writer serve file

```go
w.Header().Set("Vary", "Accept-Encoding")
w.Header().Set("Cache-Control", "public, max-age=7776000")
http.ServeFile(w, r, "manifest.json")
```

### writer write json

```go
w.Header().Set("Content-Type", "application/json")
post := &Post{
    User:    "Sau Sheong",
    Threads: []string{"first", "second", "third"},
}
json, _ := json.Marshal(post)
w.Write(json)
```

### handler example

```go
func homeHandler(w http.ResponseWriter, r *http.Request) {
	renderHTMLAuthFlashCSRF(w, r, "pages/index.html", nil)
}
```

### handler login

```go
http.HandleFunc("/login", loginHandler)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	flashMsg, _ := getFlash(w, r, flashCookie)
	if r.Method == http.MethodGet {
		tmpl := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Login</title>
		</head>
		<body>
			<h1>Login</h1>
			{{if .FlashMsg}}
				<p style="color: green;">{{.FlashMsg}}</p>
			{{end}}
			<a href="/login">Login</a>
			<a href="/signup">Signup</a>
			<a href="/logout">Logout</a>
			<form action="/login" method="post">
				{{ .csrfField }}
				<input type="email" name="email" placeholder="Email" required>
				<input type="password" name="password" placeholder="Password" required>
				<button type="submit">Login</button>
			</form>
			<a href="/change-password">Forgot password?</a>
		</body>
		</html>`

		data := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"FlashMsg":       flashMsg,
		}

		err := RenderTemplateInline(w, tmpl, data)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try letter", http.StatusInternalServerError)
		}
		return
	} else if r.Method == http.MethodPost {
		user := User{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		var hashedPassword string
		err := dbAuth.QueryRow("SELECT password FROM users WHERE email = ?", user.Email).Scan(&hashedPassword)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)) != nil {
			setFlash(w, flashCookie, "Invalid credentials")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Create a JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": user.Email,
			"exp":   time.Now().Add(24 * 30 * time.Hour).Unix(),
		})

		// Sign the JWT with a secret key
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		// Set the JWT in an HTTP-only cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    tokenString,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   true, // Enable in production (HTTPS only)
		})
		setFlash(w, flashCookie, "Login successful!")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

```

### handler logout

```go
http.HandleFunc("/logout", logoutHandler)

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the JWT cookie by setting an expired cookie with the same name
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Set the expiration time in the past
		HttpOnly: true,
		Secure:   true, // Enable in production (HTTPS only)
	})

	setFlash(w, flashCookie, "You have been logged out.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

### handler password reset

```go
"github.com/domodwyer/mailyak/v3"

const domain = "http://localhost:8080"

http.HandleFunc("/change-password", changePasswordHandler)
http.HandleFunc("/reset-password", resetPasswordHandler)

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	flashMsg, _ := getFlash(w, r, flashCookie)

	if r.Method == http.MethodGet {
		tmpl := `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Change Password</title>
        </head>
        <body>
            <h1>Change Password</h1>
			{{if .FlashMsg}}
                <p style="color: green;">{{.FlashMsg}}</p>
            {{end}}
            <a href="/login">Login</a>
            <a href="/signup">Signup</a>
            <a href="/logout">Logout</a>
            <form action="/change-password" method="post">
                {{ .csrfField }}
                <input type="email" name="email" placeholder="Email" required>
                <button type="submit">Change Password</button>
            </form>
        </body>
        </html>`

		data := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"FlashMsg":       flashMsg,
		}

		err := RenderTemplateInline(w, tmpl, data)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
		}
	} else if r.Method == http.MethodPost {
		email := r.FormValue("email")
		var exists bool
		err := dbAuth.QueryRow("SELECT COUNT(*) > 0 FROM users WHERE email = ?", email).Scan(&exists)
		if err != nil || !exists {
			setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}

		resetToken, err := encryptToken(email, []byte(secretKey))
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		// Send a password reset email
		resetLink := fmt.Sprintf(domain+"/reset-password?token=%s&email=%s", resetToken, email)
		//go sendResetEmail(email, resetLink)
		go sendResetPassword(email, resetLink)

		http.SetCookie(w, &http.Cookie{
			Name:     "reset_token",
			Value:    resetToken,
			Expires:  time.Now().Add(1 * time.Hour),
			HttpOnly: true,
			Secure:   true,
		})

		setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
	}
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reset Password</title>
        </head>
        <body>
            <h1>Reset Password</h1>
            {{if .FlashMsg}}
                <p style="color: green;">{{.FlashMsg}}</p>
            {{end}}
            <a href="/login">Login</a>
            <a href="/signup">Signup</a>
            <a href="/logout">Logout</a>
            <form action="/reset-password" method="post">
				{{ .csrfField }}
                <input type="hidden" name="token" value="{{.Token}}">
                <input type="password" name="password" placeholder="New Password" required>
                <button type="submit">Reset Password</button>
            </form>
        </body>
        </html>`
		flash, _ := getFlash(w, r, flashCookie)
		data := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"FlashMsg":       flash,
			"Token":          r.URL.Query().Get("token"),
		}

		if data["Token"] == nil {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		}

		err := RenderTemplateInline(w, tmpl, data)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
		}
		return
	} else if r.Method == http.MethodPost {
		token := r.FormValue("token")
		newPassword := r.FormValue("password")

		email, err := decryptToken(token, []byte(secretKey))
		if err != nil {
			setFlash(w, flashCookie, "Invalid or expired token")
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		_, err = dbAuth.Exec("UPDATE users SET password = ? WHERE email = ?", string(hashedPassword), email)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		setFlash(w, flashCookie, "Password reset successful!")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func sendResetPassword(email, link string) error {
	// Create a new email - specify the SMTP host:port and auth (if needed)
	mail := mailyak.New("smtp.mail.me.com:587", smtp.PlainAuth("", "andreinita@icloud.com", "kqfp-sdar-bxzw-awfu", "smtp.mail.me.com"))

	mail.To(email)
	mail.From("andreinita@icloud.com")
	mail.FromName("Localhost")

	mail.Subject("Password Reset")

	// Or set the body using a string setter
	mail.Plain().Set("Click the link to reset your password: " + link)

	// And you're done!
	if err := mail.Send(); err != nil {
		return err
	}
	return nil
}

func encryptToken(email string, secretKey []byte) (string, error) {
	plaintext := []byte(email + "|" + time.Now().Add(1*time.Hour).Format(time.RFC3339))
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptToken(token string, secretKey []byte) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(string(plaintext), "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	expiry, err := time.Parse(time.RFC3339, parts[1])
	if err != nil {
		return "", err
	}

	if time.Now().After(expiry) {
		return "", fmt.Errorf("token has expired")
	}

	return parts[0], nil
}
```

### handler signup

```go
http.HandleFunc("/signup", signupHandler)

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Signup</title>
	</head>
	<body>
		<h1>Signup</h1>
		<a href="/login">Login</a>
		<a href="/signup">Signup</a>
		<a href="/logout">Logout</a>
		<form action="/signup" method="post">
			{{ .csrfField }}
			<input type="email" name="email" placeholder="Email" required>
			<input type="password" name="password" placeholder="Password" required>
			<button type="submit">Signup</button>
		</form>
	</body>
	</html>`

		data := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		}

		err := RenderTemplateInline(w, tmpl, data)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try letter", http.StatusInternalServerError)
		}
		return
	} else if r.Method == http.MethodPost {
		user := User{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		_, err = dbAuth.Exec("INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		setFlash(w, flashCookie, "Account successfully created! Please login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
```

### http csrf

```go
const secretKey = "<!32trentadue!><!treizecisidoi!>" // 32 characters as required by csrf

// Set up CSRF protection
CSRF := csrf.Protect(
    []byte(secretKey),  // Replace with a secure key
    csrf.Secure(false), // TODO: Set to true in production (HTTPS only)
)

// Graceful shutdown handling
server := http.Server{Addr: ":8080"}
server.Handler = CSRF(http.DefaultServeMux)

go func() {
    fmt.Println("Starting server @ http://localhost:8080")
    if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
        log.Fatalf("Server failed: %v", err)
    }
}()

stop := make(chan os.Signal, 1)
signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

<-stop
log.Println("Shutting down server...")
if err := server.Close(); err != nil {
    log.Fatalf("Server shutdown error: %v", err)
}
log.Println("Server gracefully stopped.")
```

### http get url

```go
resp, err := http.Get("https://andrei.website")
if err != nil {
    // TODO
}
b, err := ioutil.ReadAll(resp.Body)
defer resp.Body.Close()
if err != nil {
    // TODO
}
fmt.Printf("%s", b)
```

### http get url data with cookie and token from browser

```go
var codestichUsername string
var codestichPassword string
var codestichSession string
var xsrfToken string
var scrapData = false

func init() {
	codestichUsername = os.Getenv("codestichUsername")
	if codestichUsername == "" {
		log.Fatal("Environment variable codestichUsername is not set")
	}

	codestichPassword = os.Getenv("codestichPassword")
	if codestichPassword == "" {
		log.Fatal("Environment variable codestichPassword is not set")
	}

	// Retrieve session and XSRF tokens from environment variables
	codestichSession = os.Getenv("codestich_session")
	if codestichSession == "" {
		log.Fatal("Environment variable codestich_session is not set")
	}

	xsrfToken = os.Getenv("XSRF_TOKEN")
	if xsrfToken == "" {
		log.Fatal("Environment variable XSRF_TOKEN is not set")
	}
}

req, err := http.NewRequest("GET", pageLink, nil)
if err != nil {
    log.Fatalln(err)
}
// Manually set the Cookie header using the values retrieved from your browser.
// Depending on the site's requirements, you might need to include additional cookies.
cookieHeader := fmt.Sprintf("codestitch_session=%s; XSRF-TOKEN=%s", codestichSession, xsrfToken)
req.Header.Set("Cookie", cookieHeader)

// Set a typical browser User-Agent header.
req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124")

// Optionally, add Referer and Origin headers if needed.
req.Header.Set("Referer", "https://codestitch.app/login")
req.Header.Set("Origin", "https://codestitch.app")

client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
    log.Fatalln(err)
}
defer resp.Body.Close()
```

### http get url with password

```go
username := "your_username"
password := "your_password"
auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

req, err := http.NewRequest("GET", pageLink, nil)
if err != nil {
    log.Fatalln(err)
}
req.Header.Add("Authorization", auth)

client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
    log.Fatalln(err)
}
defer resp.Body.Close()
```

### http handle with handler (ServeHTTP)

```go
type HelloHandler struct{}

func (h *HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello!")
}

hello := HelloHandler{}
http.Handle("/hello", &hello)
```

### http handle with handlerfunc

```go
type dollars float32

func (d dollars) String() string { return fmt.Sprintf("$%.2f", d) }

type database map[string]dollars

func (db database) list(w http.ResponseWriter, req *http.Request) {
	for item, price := range db {
		fmt.Fprintf(w, "%s: %s\n", item, price)
	}
}

func (db database) price(w http.ResponseWriter, req *http.Request) {
	item := req.URL.Query().Get("item")
	price, ok := db[item]
	if !ok {
		w.WriteHeader(http.StatusNotFound) // 404
		fmt.Fprintf(w, "no such item: %q\n", item)
		return
	}
	fmt.Fprintf(w, "%s\n", price)
}

db := database{"shoes": 50, "socks": 5}
http.Handle("/list", http.HandlerFunc(db.list))
http.Handle("/price", http.HandlerFunc(db.price))
log.Fatal(http.ListenAndServe("localhost:8000", nil))
```

### http hanler (ServeHTTP)

```go
type dollars float32

func (d dollars) String() string { return fmt.Sprintf("$%.2f", d) }

type database map[string]dollars

//!+handler
func (db database) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/list":
		for item, price := range db {
			fmt.Fprintf(w, "%s: %s\n", item, price)
		}
	case "/price":
		item := req.URL.Query().Get("item")
		price, ok := db[item]
		if !ok {
			w.WriteHeader(http.StatusNotFound) // 404
			fmt.Fprintf(w, "no such item: %q\n", item)
			return
		}
		fmt.Fprintf(w, "%s\n", price)
	default:
		w.WriteHeader(http.StatusNotFound) // 404
		fmt.Fprintf(w, "no such page: %s\n", req.URL)
	}
}

db := database{"shoes": 50, "socks": 5}
log.Fatal(http.ListenAndServe("localhost:8000", db))
```

### http https production

```go
// production SSL: "golang.org/x/crypto/acme/autocert"
http.HandleFunc("/", home)

// production SSL
certManager := autocert.Manager{
    Prompt:     autocert.AcceptTOS,
    HostPolicy: autocert.HostWhitelist(fmt.Sprint("andrei.website")), // Your domain here
    Cache:      autocert.DirCache("certs"),                             // Folder for storing certificates
}

// starting up the server
httpsServer := &http.Server{
    Addr:           server.Config.PortSSL,
    TLSConfig:      &tls.Config{GetCertificate: certManager.GetCertificate},
    //Handler:        new(middlewares.GzipMiddleware),
    ReadTimeout:    time.Duration(60 * int64(time.Second)),
    WriteTimeout:   time.Duration(60 * int64(time.Second)),
    MaxHeaderBytes: 1 << 20,
}

go httpsServer.ListenAndServeTLS("", "")
log.Fatalln(http.ListenAndServe(":http", certManager.HTTPHandler(nil)))
```

### http https production and localhost (needs improvment)

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/andrei/_skeleton/middlewares"
	"github.com/andrei/_skeleton/routes"
	"github.com/andrei/_skeleton/server"
	"github.com/andrei/_skeleton/server/dev"
	"golang.org/x/crypto/acme/autocert"
)

func init() {
	if server.Config.Dev.IsActive {
		if _, err := os.Stat("server/dev/cert.pem"); os.IsNotExist(err) {
			// file does not exist
			dev.GenerateSSL4Dev()
			fmt.Println("✔ SSL for localhost created")
			fmt.Println("🛑 Add server/dev/cert.pem to keychain certificates and always trust")
		}
	}
	fmt.Printf("Navigate to: http://%s\n", server.Config.Host)
}

func main() {

	// routes
	http.HandleFunc("/", routes.Home)
	//http.HandleFunc("/favicon.ico", routes.FaviconHandler)
	http.HandleFunc("/robots.txt", routes.RobotsText)

	// static files
	http.Handle("/public/", middlewares.Cache(http.StripPrefix("/public/", http.FileServer(http.Dir("static/public")))))

	// localhost SSL
	if server.Config.Dev.IsActive {
		httpServer := &http.Server{
			Addr:           server.Config.Port,
			Handler:        http.HandlerFunc(redirectToHTTPS),
			ReadTimeout:    time.Duration(60 * int64(time.Second)),
			WriteTimeout:   time.Duration(60 * int64(time.Second)),
			MaxHeaderBytes: 1 << 20,
		}

		// starting up the server
		httpsServer := &http.Server{
			Addr:           server.Config.PortSSL,
			Handler:        new(middlewares.GzipMiddleware),
			ReadTimeout:    time.Duration(60 * int64(time.Second)),
			WriteTimeout:   time.Duration(60 * int64(time.Second)),
			MaxHeaderBytes: 1 << 20,
		}

		go httpsServer.ListenAndServeTLS("server/dev/cert.pem", "server/dev/key.pem")
		log.Fatalln(httpServer.ListenAndServe())
	}

	// production SSL
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(fmt.Sprint(server.Config.Host)), // Your domain here
		Cache:      autocert.DirCache("certs"),                             // Folder for storing certificates
	}

	// starting up the server
	httpsServer := &http.Server{
		Addr:           server.Config.PortSSL,
		TLSConfig:      &tls.Config{GetCertificate: certManager.GetCertificate},
		Handler:        new(middlewares.GzipMiddleware),
		ReadTimeout:    time.Duration(60 * int64(time.Second)),
		WriteTimeout:   time.Duration(60 * int64(time.Second)),
		MaxHeaderBytes: 1 << 20,
	}

	go httpsServer.ListenAndServeTLS("", "")
	log.Fatalln(http.ListenAndServe(":http", certManager.HTTPHandler(nil)))
}

// redirectToHTTPS redirects HTTP connections to HTTPS on localhost
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+server.Config.Host+server.Config.PortSSL+r.RequestURI, http.StatusMovedPermanently)
}
```

### http redirect to ssl

```go
url := "https://" + r.Host + r.URL.String()
http.Redirect(w, r, url, http.StatusMovedPermanently)
```

### http serve static from folder

```go
http.Handle("/static", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
```

### http serve static with embedd

```go
//go:embed public/*
var publicFiles embed.FS

publicFiles, err := fs.Sub(publicFiles, "public")
if err != nil {
    log.Fatal(err)
}

http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.FS(publicFiles))))
```

### http with graceful shutdown

```go
/* index functionality */
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // TODO
})

// Graceful shutdown handling
server := &http.Server{Addr: ":8000"}

go func() {
    log.Println("Starting server on :8000")
    if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
        log.Fatalf("Server failed: %v", err)
    }
}()

stop := make(chan os.Signal, 1)
signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

<-stop
log.Println("Shutting down server...")
if err := server.Close(); err != nil {
    log.Fatalf("Server shutdown error: %v", err)
}
log.Println("Server gracefully stopped.")
```

### htttp and https localhost

```go
// localhost SSL
localhost := true

http.HandleFunc("/", home)

if localhost {
    httpServer := &http.Server{
        Addr: ":80",
        Handler:        http.HandlerFunc(redirectToHTTPS),
        ReadTimeout:    time.Duration(60 * int64(time.Second)),
        WriteTimeout:   time.Duration(60 * int64(time.Second)),
        MaxHeaderBytes: 1 << 20,
    }

    httpsServer := &http.Server{
        Addr: ":443",
        //Handler:        new(middlewares.GzipMiddleware),
        ReadTimeout:    time.Duration(60 * int64(time.Second)),
        WriteTimeout:   time.Duration(60 * int64(time.Second)),
        MaxHeaderBytes: 1 << 20,
    }

    go log.Fatalln(httpsServer.ListenAndServeTLS("cert.pem", "key.pem"))
    log.Fatalln(httpServer.ListenAndServe())
}
```

### server get ip

```go
func getIP() string {
	host, _ := os.Hostname()
	addrs, _ := net.LookupIP(host)
	ip := ""
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			if ipv4.String() == "127.0.0.1" {
				continue
			}
			ip = ipv4.String()
			break
		}
	}
	return ip
}
```

### url join

```go
func joinURL(base, relative string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("error parsing base URL: %v", err)
	}

	relativePath := strings.TrimSpace(relative)
	relativeURL, err := url.Parse(relativePath)
	if err != nil {
		return "", fmt.Errorf("error parsing relative URL: %v", err)
	}

	finalURL := baseURL.ResolveReference(relativeURL)
	return finalURL.String(), nil
}
```

### url parameter for no cache

```go
dynamicURL := "/content?" + time.Now().UnixNano()
```

### context check if authenticated

```go
user, ok := r.Context().Value("auth").(db.User)
if !ok || user.Email == "" {
    cookies.FlashSetWithRedirect(w, r, "Please login", "/login")
    return
}
```

### cookie package

```go
package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

func Write(w http.ResponseWriter, cookie http.Cookie) error {
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}

	http.SetCookie(w, &cookie)

	return nil
}

func Read(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	return string(value), nil
}

func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey string) error {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)

	cookie.Value = string(signature) + cookie.Value

	return Write(w, cookie)
}

func ReadSigned(r *http.Request, name string, secretKey string) (string, error) {
	signedValue, err := Read(r, name)
	if err != nil {
		return "", err
	}

	if len(signedValue) < sha256.Size {
		return "", ErrInvalidValue
	}

	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", ErrInvalidValue
	}

	return value, nil
}

func WriteEncrypted(w http.ResponseWriter, cookie http.Cookie, secretKey string) error {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	cookie.Value = string(encryptedValue)

	return Write(w, cookie)
}

func ReadEncrypted(r *http.Request, name string, secretKey string) (string, error) {
	encryptedValue, err := Read(r, name)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()

	if len(encryptedValue) < nonceSize {
		return "", ErrInvalidValue
	}

	nonce := encryptedValue[:nonceSize]
	ciphertext := encryptedValue[nonceSize:]

	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", ErrInvalidValue
	}

	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		return "", ErrInvalidValue
	}

	if expectedName != name {
		return "", ErrInvalidValue
	}

	return value, nil
}

```

### cookie set flash and get flash

```go
const flashCookie = "flash"

// setFlash sets a flash message in a cookie
func setFlash(w http.ResponseWriter, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   1, // The cookie will be deleted after 1 second
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, c)
}

// getFlash retrieves and clears a flash message from a cookie
func getFlash(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		switch err {
		case http.ErrNoCookie:
			return "", nil // No flash message
		default:
			return "", err
		}
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1, // Delete the cookie
		HttpOnly: true,
		Secure:   true,
	})

	return c.Value, nil
}

setFlash(w, flashCookie, "Invalid credentials")

flashMsg, _ := getFlash(w, r, flashCookie)

data := map[string]interface{}{
    "FlashMsg":  flashMsg,
}

{{if .FlashMsg}}
    <p style="color: green;">{{.FlashMsg}}</p>
{{end}}
```

### cookies and flash (package)

```go
package cookies

import (
	"encoding/base64"
	"net/http"
	"play/internals/config"
	"time"
)

// Configurable settings (inject via config package or constants)
var (
	secureCookies bool
)

func init() {
	if config.Config.IsProd {
		secureCookies = true
	}
}

// Set sets a secure cookie with optional expiration.
func Set(w http.ResponseWriter, name, value string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.URLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		Domain:   config.Config.Domain,
		Expires:  expiry,
		Secure:   secureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Get retrieves a cookie by name without modifying it.
func Get(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}

func GetValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(value), nil
}

// Delete removes a cookie immediately.
func Delete(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     "/",
		Domain:   config.Config.Domain,
		MaxAge:   -1,
		Secure:   secureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// FlashSet sets a short-lived flash cookie.
func FlashSet(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.URLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		Domain:   config.Config.Domain,
		MaxAge:   10,
		Secure:   secureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// FlashGet retrieves a flash message and deletes it in the same request cycle.
func FlashGet(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", nil
		}
		return "", err
	}

	// Immediately clear after reading
	Delete(w, name)

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(value), nil
}

```

### url get query parameter

```go
r.URL.Query().Get("token")
```

### url extract path

```go
r.RequestURI
```

### writer serve favicon from embedded

```go
mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
file, readErr := f.ReadFile("assets/favicon.ico")
if readErr != nil {
    slog.Warn("Failed to read favicon.ico", "error", readErr, "path", r.URL.Path)
    http.NotFound(w, r)
    return
}
w.Header().Set("Content-Type", "image/x-icon")
w.Write(file)
})
```

