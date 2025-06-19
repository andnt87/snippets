# MyGo Snippets

- Directory: go
- File: MyGo Snippets

## Templates

### snippet app

```go
package main

import (
	"database/sql"
	_ "embed"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"os"
	"time"
)

const isProduction = false

var db *sql.DB
var logger *log.Logger

type Component struct {
	ID        int    `json:"id"`
	URL       string `json:"url"`
	Name      string `json:"name"`
	HTML      string `json:"html"`
	JS        string `json:"js"`
	CSS       string `json:"css"`
	Less      string `json:"less"`
	Sass      string `json:"sass"`
	CSSDark   string `json:"css_dark"`
	LessDark  string `json:"less_dark"`
	SassDark  string `json:"sass_dark"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "file:codestich.db?cache=shared&mode=rwc&_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS components (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			html TEXT NOT NULL,
			js TEXT NOT NULL,
			css TEXT NOT NULL,
			less TEXT NOT NULL,
			sass TEXT NOT NULL,
			css_dark TEXT NOT NULL,
			less_dark TEXT NOT NULL,
			sass_dark TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func closeDB() {
	err := db.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Closing database without errors")
}

func main() {
	// Open a file for logging
	file, err := os.OpenFile("logfile.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// Create a multi-writer to log to both file and stdout
	var multiWriter io.Writer
	if !isProduction {
		multiWriter = io.MultiWriter(file, os.Stdout)
	} else {
		multiWriter = file
	}

	// Create a new logger
	logger = log.New(multiWriter, "", log.LstdFlags)

	initDB()
	defer closeDB()
}

```

### snippet boileprlate + auth system

```go
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/NYTimes/gziphandler"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/csrf"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/domodwyer/mailyak/v3"
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
)

const isProduction = false
const domain = "http://localhost:8080"

// rate limit middleware
const rateLimitDuration = 1 * time.Minute // Time frame for rate limiting
const maxRequests = 100                   // Maximum number of requests per time frame

// rate limit signup
const rateLimitDurationSignup = 1 * time.Minute // Time frame for rate limiting
const maxRequestsSignup = 1                     // Maximum number of requests per time frame

const flashCookie = "flash"
const tokenCookieValidate = "token_validate"

const levelInfo = "info"
const levelWarning = "warning"
const levelError = "error"

var secretKey string
var smtpPass string
var smtpUser string

//go:embed reload.html
var reloadHtmlFile []byte

var dbAuth *sql.DB
var logger *log.Logger

// templates
var templates *template.Template
var templateDir = "app/src"
var templateFiles = make(map[string]bool)

// websocket
var upgrader = websocket.Upgrader{}
var connections = make(map[*websocket.Conn]bool)
var mu sync.Mutex

// rate limit middleware
var muRateLimit sync.Mutex
var rateLimitMap = make(map[string]int)

// signupRateLimitMax
var muSignupRateLimit sync.Mutex
var rateSignupLimitMap = make(map[string]int)

type User struct {
	Id        string    `json:"id"`
	IsAuth    bool      `json:"isAuth"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	UserType  string    `json:"user_type"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func init() {
	// Attempt to load the secret key from the environment variable.
	secretKey = os.Getenv("secretKey")
	if secretKey == "" {
		log.Fatal("Environment variable secretKey is not set")
	}

	// Attempt to load the email password from the environment variable.
	smtpPass = os.Getenv("smtpPass")
	if smtpPass == "" {
		log.Fatal("Environment variable emailPassword is not set")
	}

	smtpUser = os.Getenv("smtpUser")
	if smtpUser == "" {
		log.Fatal("Environment variable emailPassword is not set")
	}

	fmt.Println("Successfully loaded secretKey and emailPassword from environment variables")
}

func watchDirectory(directory string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := watcher.Add(path); err != nil {
				log.Printf("Error watching directory: %s, %v", path, err)
			} else {
				fmt.Println("Watching:", path)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Watching directory:", directory)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 && strings.HasSuffix(event.Name, ".html") {
				fmt.Println("HTML file changed:", event.Name)
				if err := loadTemplates(); err != nil {
					log.Println("Failed to reload templates:", err)
				}
				notifyClients()
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				fileInfo, err := os.Stat(event.Name)
				if err == nil && fileInfo.IsDir() {
					watcher.Add(event.Name)
					fmt.Println("Added new directory to watch:", event.Name)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error watching files:", err)
		}
	}
}

func renderHTML(w http.ResponseWriter, page string, data map[string]interface{}) {
	err := templates.ExecuteTemplate(w, page, data)
	if err != nil {
		logToFileWithCaller(levelError, err.Error())
		http.Error(w, "Please try letter", http.StatusInternalServerError)
	}
}

// renderHTMLAuthFlashCSRF renders the html checking for authentication and flash cookie
func renderHTMLAuthFlashCSRF(w http.ResponseWriter, r *http.Request, page string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}

	// Retrieve authentication details from the context
	user, ok := r.Context().Value("auth").(User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	flashMsg, _ := getFlash(w, r, flashCookie)

	data["UserEmail"] = user.Email
	data["UserType"] = user.UserType
	data["UserVerified"] = user.Verified
	data["IsAuth"] = user.IsAuth
	data["FlashMsg"] = flashMsg
	data[csrf.TemplateTag] = csrf.TemplateField(r)

	err := templates.ExecuteTemplate(w, page, data)
	if err != nil {
		logToFileWithCaller(levelError, err.Error())
		http.Error(w, "Please try later", http.StatusInternalServerError)
	}
}

func loadTemplates() error {
	tmpl := template.New("")

	err := filepath.WalkDir(templateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".html" {
			relPath, err := filepath.Rel(templateDir, path)
			if err != nil {
				return err
			}
			relPath = filepath.ToSlash(relPath) // Ensure cross-platform compatibility
			if strings.HasPrefix(relPath, "pages/") {
				templateFiles[relPath] = true
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = tmpl.New(relPath).Parse(string(content))
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}
	templates = tmpl
	log.Println("Templates reloaded successfully.")
	return nil
}

func notifyClients() {
	mu.Lock()
	defer mu.Unlock()
	for conn := range connections {
		err := conn.WriteMessage(websocket.TextMessage, []byte("reload"))
		if err != nil {
			log.Println("Deleting connection:", err)
			conn.Close()
			delete(connections, conn)
		}
	}
}

// CORS Middleware
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := domain
		if isProduction {
			origin = "https://" + strings.TrimPrefix(domain, "http://")
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if isProduction {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("X-XSS-Protection", "0") // Deprecated, modern browsers ignore it
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Error Handling Middleware
func errorHandling(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Example Rate Limiting Middleware
func rateLimiting(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		muRateLimit.Lock()
		defer muRateLimit.Unlock()

		clientIP := r.RemoteAddr
		count, exists := rateLimitMap[clientIP]

		if exists && count >= maxRequests {
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		if !exists {
			go resetRateLimit(clientIP)
		}

		rateLimitMap[clientIP]++
		//fmt.Println("Rate Limit Logic: ", clientIP, rateLimitMap[clientIP])
		next.ServeHTTP(w, r)
	})
}

func resetRateLimit(clientIP string) {
	time.Sleep(rateLimitDuration)
	muRateLimit.Lock()
	defer muRateLimit.Unlock()
	delete(rateLimitMap, clientIP)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			ctx := context.WithValue(r.Context(), "auth", User{})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Parse and validate the JWT
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(secretKey), nil
		})
		if err != nil || !token.Valid {
			ctx := context.WithValue(r.Context(), "auth", User{})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Extract claims from the JWT
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			ctx := context.WithValue(r.Context(), "auth", User{})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Check expiration
		if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
			ctx := context.WithValue(r.Context(), "auth", User{})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Create User struct from claims
		authData := User{
			Email:    claims["email"].(string),
			UserType: claims["user_type"].(string),
			Verified: claims["verified"].(bool),
			IsAuth:   claims["isAuth"].(bool),
		}

		// Attach the auth data to the request context
		ctx := context.WithValue(r.Context(), "auth", authData)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Custom logger to include file and line number
func logToFileWithCaller(level string, msg string) {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}
	logger.Printf("%s: %s [%s:%d]\n", level, msg, file, line)
}

func initAuthDB() {
	var err error
	dbAuth, err = sql.Open("sqlite3", "file:auth.db?cache=shared&mode=rwc&_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Configure connection pool
	dbAuth.SetMaxOpenConns(25)
	dbAuth.SetMaxIdleConns(25)
	dbAuth.SetConnMaxLifetime(5 * time.Minute)

	_, err = dbAuth.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			user_type TEXT NOT NULL DEFAULT 'user', -- Can be 'admin', 'user', etc
			verified BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func closeAuthDB() {
	err := dbAuth.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Closing database without errors")
}

func setCookie(w http.ResponseWriter, name, value string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getCookie(w http.ResponseWriter, r *http.Request, name string) (*http.Cookie, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}
	setCookie(w, name, "", time.Now().Add(-1*time.Hour))
	return cookie, nil
}

// setFlash sets a flash message in a cookie
func setFlash(w http.ResponseWriter, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   10, // The cookie will be deleted after 10 seconds
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
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

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1, // Delete the cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return c.Value, nil
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

func verifyTokens(token1, token2 string) (string, error) {
	email1, err := decryptToken(token1, []byte(secretKey))
	if err != nil {
		return "", err
	}

	email2, err := decryptToken(token2, []byte(secretKey))
	if err != nil {
		return "", err
	}

	if email1 != email2 {
		return "", errors.New("tokens don't match")
	}
	return email1, nil
}

func emailSendLink(email, link string) error {
	// Create a new email - specify the SMTP host:port and auth (if needed)
	mail := mailyak.New("smtp.mail.me.com:587", smtp.PlainAuth("", smtpUser, smtpPass, "smtp.mail.me.com"))

	mail.To(email)
	mail.From(smtpUser)
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

// verifyUserEmail sends a verification email: verifyUserEmail(w, user, "/urlPath")
func verifyUserEmail(w http.ResponseWriter, email, urlPath string) error {
	resetToken, err := encryptToken(email, []byte(secretKey))
	if err != nil {
		logToFileWithCaller(levelError, err.Error())
		return err
	}

	// Send a password reset email
	resetLink := fmt.Sprintf(domain+urlPath+"?token=%s", resetToken)
	setCookie(w, tokenCookieValidate, resetToken, time.Now().Add(1*time.Hour)) // TODO: insert to verification_tokens

	if isProduction {
		go func() {
			err = emailSendLink(email, resetLink)
			if err != nil {
				logToFileWithCaller(levelError, err.Error())
				setCookie(w, tokenCookieValidate, "", time.Now().Add(-time.Hour))
			}
		}()
	} else {
		logToFileWithCaller(levelInfo, resetLink)
	}
	return err
}

func signupRateLimitMax(r *http.Request) {
	muSignupRateLimit.Lock()
	defer muSignupRateLimit.Unlock()

	clientIP := r.RemoteAddr
	_, exists := rateSignupLimitMap[clientIP]

	if !exists {
		go resetSignupRateLimit(clientIP)
	}

	rateSignupLimitMap[clientIP]++
}

func checkSignupRateLimit(r *http.Request) bool {
	muSignupRateLimit.Lock()
	defer muSignupRateLimit.Unlock()
	clientIP := r.RemoteAddr
	count, exists := rateSignupLimitMap[clientIP]
	if exists && count >= maxRequestsSignup {
		return true
	}
	return false
}

func resetSignupRateLimit(clientIP string) {
	time.Sleep(rateLimitDurationSignup)
	muSignupRateLimit.Lock()
	defer muSignupRateLimit.Unlock()
	delete(rateSignupLimitMap, clientIP)
}

func checkPasswordStrength(password string) bool {
	if len(password) < 12 {
		return false
	}
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}

func main() {
	// Open a file for logging
	file, err := os.OpenFile("logfile.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// Create a multi-writer to log to both file and stdout
	var multiWriter io.Writer
	if !isProduction {
		multiWriter = io.MultiWriter(file, os.Stdout)
	} else {
		multiWriter = file
	}

	// Create a new logger
	logger = log.New(multiWriter, "", log.LstdFlags)

	initAuthDB()
	defer closeAuthDB()

	if err := loadTemplates(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { // avoid duplicate request
		http.ServeFile(w, r, "./public/favicon.ico")
	})

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/signup", signupHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/change-password", changePasswordHandler)
	mux.HandleFunc("/reset-password", resetPasswordHandler)
	mux.HandleFunc("/delete-account", deleteAccountHandler)
	mux.HandleFunc("/confirm-account", confirmAccountHandler)
	mux.HandleFunc("/make-admin", makeAdminHandler)
	mux.HandleFunc("/users", getAllUsersHandler)

	mux.HandleFunc("/blog/", handleDynamic)

	var handler http.Handler = mux
	handler = gziphandler.GzipHandler(handler)
	handler = cors(handler)
	handler = securityHeaders(handler)
	handler = errorHandling(handler)
	//handler = rateLimiting(handler)
	handler = authMiddleware(handler)
	CSRF := csrf.Protect(
		[]byte(secretKey),
		csrf.Secure(isProduction),
	)
	handler = CSRF(handler)

	server := &http.Server{
		Addr:           ":8080",
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	if !isProduction {
		go watchDirectory(templateDir)

		mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
			upgrader.CheckOrigin = func(r *http.Request) bool { return true }
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Println("WebSocket upgrade error:", err)
				return
			}

			mu.Lock()
			connections[conn] = true
			mu.Unlock()

			fmt.Println("New WebSocket connection")
		})

		mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write(reloadHtmlFile)
		})

		go func() {
			log.Println("Starting server on :8080")
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Server failed: %v", err)
			}
		}()
	} else { // production
		// Set up autocert for Let's Encrypt
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache("/var/www/.cache"), // Ensure this directory is writable
		}

		// Start HTTP server on port 80 for challenges and redirection
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { // '/' is set on http (and not mux)
				target := "https://" + r.Host + r.URL.Path
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
			})
			log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(nil)))
		}()

		server.Addr = ":443"
		server.Handler = handler
		server.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

		go func() {
			log.Println("Starting secure server on :443")
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Server failed: %v", err)
			}
		}()
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down server...")
	if err := server.Close(); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Server gracefully stopped.")
}

func handleDynamic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = filepath.ToSlash(path) // Ensure cross-platform compatibility
	templateFile := fmt.Sprintf("pages/%s.html", path)

	if ok := templateFiles[templateFile]; !ok {
		if strings.HasSuffix(path, "/") {
			path += "index" // route is like /blog/tennis/
		} else {
			path += "/index" // route is like /blog/tennis
		}
		templateFile = fmt.Sprintf("pages/%s.html", path)
	}

	renderHTMLAuthFlashCSRF(w, r, templateFile, nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	renderHTMLAuthFlashCSRF(w, r, "pages/index.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderHTMLAuthFlashCSRF(w, r, "pages/login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		user := User{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		var dbUser struct {
			Password string
			UserType string
			Verified bool
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := dbAuth.QueryRowContext(ctx, "SELECT password, user_type, verified FROM users WHERE email = ?", user.Email).
			Scan(&dbUser.Password, &dbUser.UserType, &dbUser.Verified)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)) != nil {
			setFlash(w, flashCookie, "Invalid credentials")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if account is verified
		if !dbUser.Verified {
			// Send verification email again
			if err = verifyUserEmail(w, user.Email, "/confirm-account"); err != nil {
				logToFileWithCaller(levelError, err.Error())
				http.Error(w, "Please try later", http.StatusInternalServerError)
				return
			}
			setFlash(w, flashCookie, "Account not verified. We've sent a new verification email.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Create a JWT with additional claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email":     user.Email,
			"user_type": dbUser.UserType,
			"verified":  dbUser.Verified,
			"isAuth":    true,
			"iat":       time.Now().Unix(),                          // Issued at
			"exp":       time.Now().Add(24 * 30 * time.Hour).Unix(), // Expiry (30 days)
			"nbf":       time.Now().Unix(),                          // Not before
		})

		// Sign the JWT with a strong secret key
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		// Set the JWT in a secure cookie
		setCookie(w, "jwt", tokenString, time.Now().Add(24*time.Hour))
		setFlash(w, flashCookie, "Login successful!")

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderHTMLAuthFlashCSRF(w, r, "pages/signup.html", nil)
		return
	} else if r.Method == http.MethodPost {
		if checkSignupRateLimit(r) {
			setFlash(w, flashCookie, "Too many attempts to signup. Please try again after 24 hours.")
			http.Redirect(w, r, "/signup", http.StatusSeeOther)
			return
		}

		user := User{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		// TODO: validate email

		if !checkPasswordStrength(user.Password) {
			setFlash(w, flashCookie, "Password must be at least 8 characters long and contain at least one uppercase letter and one lowercase letter.")
			http.Redirect(w, r, "/signup", http.StatusSeeOther)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tx, err := dbAuth.BeginTx(ctx, nil)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		var exists bool
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM users WHERE email = ?", user.Email).Scan(&exists)
		if err != nil {
			tx.Rollback()
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		if exists {
			err = tx.QueryRowContext(ctx, "SELECT verified FROM users WHERE email = ?", user.Email).Scan(&user.Verified)
			if err != nil {
				tx.Rollback()
				logToFileWithCaller(levelError, err.Error())
				http.Error(w, "Please try later", http.StatusInternalServerError)
				return
			}
			if user.Verified {
				tx.Rollback()
				setFlash(w, flashCookie, "Login! An account with the provided email address already exists.")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		if !exists {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				tx.Rollback()
				logToFileWithCaller(levelError, err.Error())
				http.Error(w, "Please try later", http.StatusInternalServerError)
				return
			}

			_, err = tx.ExecContext(ctx, "INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
			if err != nil {
				tx.Rollback()
				logToFileWithCaller(levelError, err.Error())
				http.Error(w, "Please try later", http.StatusInternalServerError)
				return
			}

			// TODO: insert into verification_tokens
		}

		if err = verifyUserEmail(w, user.Email, "/confirm-account"); err != nil {
			tx.Rollback()
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		err = tx.Commit()
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		signupRateLimitMax(r)

		setFlash(w, flashCookie, "An activation email has been sent to your provided email address.")
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the JWT cookie by setting an expired cookie with the same name
	setCookie(w, "jwt", "", time.Now().Add(-time.Hour))
	setFlash(w, flashCookie, "Successfully logout")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderHTMLAuthFlashCSRF(w, r, "pages/change-password.html", nil)
		return
	} else if r.Method == http.MethodPost {
		email := r.FormValue("email")

		var exists bool
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := dbAuth.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM users WHERE email = ?", email).Scan(&exists)
		if err != nil || !exists {
			setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}

		if err = verifyUserEmail(w, email, "/reset-password"); err != nil {
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
	}
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Token": r.URL.Query().Get("token"),
		}

		if data["Token"] == nil {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		}

		renderHTMLAuthFlashCSRF(w, r, "pages/reset-password.html", data)
		return
	} else if r.Method == http.MethodPost {
		token := r.FormValue("token")
		newPassword := r.FormValue("password")
		tokenFromCookie, err := getCookie(w, r, "reset_token")
		if err != nil {
			setFlash(w, flashCookie, "Invalid or expired token")
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}

		email, err := verifyTokens(token, tokenFromCookie.Value)
		if err != nil || email == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = dbAuth.ExecContext(ctx, "UPDATE users SET password = ? WHERE email = ?", string(hashedPassword), email)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		setFlash(w, flashCookie, "Password reset successful!")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("auth").(User)
	if !ok || !user.IsAuth {
		setFlash(w, flashCookie, "Please login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := dbAuth.QueryContext(ctx, "SELECT id, email, user_type FROM users")
	if err != nil {
		logToFileWithCaller(levelError, err.Error())
		http.Error(w, "Please try later", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Id, &user.Email, &user.UserType); err != nil {
			logToFileWithCaller(levelError, err.Error())
			continue
		}
		users = append(users, user)
	}

	data := map[string]interface{}{
		"users": users,
	}

	renderHTMLAuthFlashCSRF(w, r, "pages/users.html", data)
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("auth").(User)
	if !ok || !user.IsAuth {
		setFlash(w, flashCookie, "Please login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		renderHTMLAuthFlashCSRF(w, r, "pages/delete-user.html", nil)
		return
	} else if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		emailFromContext := user.Email

		if email != emailFromContext {
			setFlash(w, flashCookie, "Invalid credentials")
			http.Redirect(w, r, "/delete-account", http.StatusSeeOther)
			return
		}

		// check password with database password
		var hashedPassword string
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := dbAuth.QueryRowContext(ctx, "SELECT password FROM users WHERE email = ?", email).Scan(&hashedPassword)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
			setFlash(w, flashCookie, "Invalid credentials")
			http.Redirect(w, r, "/delete-account", http.StatusSeeOther)
			return
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = dbAuth.ExecContext(ctx, "DELETE FROM users WHERE email = ?", email)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}

		setCookie(w, "jwt", "", time.Now().Add(-time.Hour))
		setFlash(w, flashCookie, "User deleted successfully")

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func confirmAccountHandler(w http.ResponseWriter, r *http.Request) {
	tokenFromUrl := r.URL.Query().Get("token")
	tokenFromCookie, err := getCookie(w, r, tokenCookieValidate)
	if err != nil || tokenFromUrl == "" || tokenFromUrl != tokenFromCookie.Value {
		renderHTMLAuthFlashCSRF(w, r, "pages/confirm-account.html", nil)
		return
	}

	email, err := verifyTokens(tokenFromUrl, tokenFromCookie.Value)
	if err != nil || email == "" {
		setFlash(w, flashCookie, "Invalid or expired token. Please sign up again to get a new email with a confirmation link.")
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dbAuth.ExecContext(ctx, "UPDATE users SET verified = ? WHERE email = ?", true, email)
	if err != nil {
		logToFileWithCaller(levelError, err.Error())
		http.Error(w, "Please try later", http.StatusInternalServerError)
		return
	}

	renderHTMLAuthFlashCSRF(w, r, "pages/confirm-account.html", nil)
}

func makeAdminHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("auth").(User)
	if !ok || (!user.IsAuth && user.UserType == "admin") {
		setFlash(w, flashCookie, "Please login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		renderHTMLAuthFlashCSRF(w, r, "pages/make-admin.html", nil)
		return
	} else if r.Method == http.MethodPost {
		email := r.FormValue("email")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := dbAuth.ExecContext(ctx, "UPDATE users SET user_type = ? WHERE email = ?", "admin", email)
		if err != nil {
			logToFileWithCaller(levelError, err.Error())
			http.Error(w, "Please try later", http.StatusInternalServerError)
			return
		}
		setFlash(w, flashCookie, fmt.Sprintf("User %s is now an admin", email))
		http.Redirect(w, r, "/users", http.StatusSeeOther)
	}
}

```

### snippet boilerplate

```go
package main

import (
	"bot/middlewares"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed reload.html
var reloadHtmlFile []byte

// app
var logger *log.Logger
var templs *template.Template
var pages = make(map[string]bool)

// websocket
var upgrader = websocket.Upgrader{}
var connections = make(map[*websocket.Conn]bool)
var mu sync.Mutex

func init() {
	setupLog(false)
	parseTemplates()
}

func main() {
	// server
	mux := http.NewServeMux()
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { // avoid duplicate request
		http.ServeFile(w, r, "public/favicon.ico")
	})

	mux.HandleFunc("/", home)
	mux.HandleFunc("/blog/", dynamic)

	reloadByWebSocket(mux)

	server := &http.Server{
		Addr:           ":8080",
		Handler:        middlewares.Recover(mux),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	go func() {
		log.Println("Starting server on :8080")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	gracefulShutdown(server)
}

func gracefulShutdown(server *http.Server) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	log.Println("Server gracefully stopped.")
}

func watchDirectory(directory string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := watcher.Add(path); err != nil {
				log.Printf("Error watching directory: %s, %v", path, err)
			} else {
				fmt.Println("Watching:", path)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	eventCache := make(map[string]time.Time)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 && strings.HasSuffix(event.Name, ".html") {
				now := time.Now()
				if lastEventTime, exists := eventCache["reload"]; exists && now.Sub(lastEventTime) < 100*time.Millisecond {
					continue
				}
				eventCache["reload"] = now
				if err := parseTemplates(); err != nil {
					log.Println("Failed to reload templates:", err)
				}
				notifyClients()
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				fileInfo, err := os.Stat(event.Name)
				if err == nil && fileInfo.IsDir() {
					watcher.Add(event.Name)
					fmt.Println("Added new directory to watch:", event.Name)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error watching files:", err)
		}
	}
}

func reloadByWebSocket(mux *http.ServeMux) {
	go watchDirectory("html")

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader.CheckOrigin = func(r *http.Request) bool { return true }
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket upgrade error:", err)
			return
		}

		mu.Lock()
		connections[conn] = true
		mu.Unlock()

		fmt.Println("New WebSocket connection")
	})

	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(reloadHtmlFile)
	})
}

func notifyClients() {
	mu.Lock()
	defer mu.Unlock()
	for conn := range connections {
		err := conn.WriteMessage(websocket.TextMessage, []byte("reload"))
		if err != nil {
			log.Println("Deleting connection:", err)
			conn.Close()
			delete(connections, conn)
		}
	}
}

func parseTemplates() error {
	templs = template.New("")

	err := filepath.WalkDir("html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".html" {
			relPath, err := filepath.Rel("html", path)
			if err != nil {
				return err
			}
			relPath = filepath.ToSlash(relPath) // Ensure cross-platform compatibility
			if strings.HasPrefix(relPath, "pages/") {
				pages[relPath] = true
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = templs.New(relPath).Parse(string(content))
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}
	log.Println("Templates reloaded successfully.")
	return nil
}

// setupLog creates and returns a new *log.Logger instance and a cleanup function.
// Logs are written to both app.log and stdout unless production is true.
func setupLog(production bool) (cleanup func(), err error) {
	var logFile *os.File
	logFile, err = os.OpenFile("bot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	cleanup = func() {
		if cerr := logFile.Close(); cerr != nil {
			log.Printf("Error closing log file: %v", cerr)
		}
	}

	var writer io.Writer
	if production {
		writer = logFile
	} else {
		writer = io.MultiWriter(os.Stdout, logFile)
	}

	logger = log.New(writer, "", log.Ldate|log.Ltime|log.Lshortfile) // adds timestamp + file:line
	return
}

func renderHTML(w http.ResponseWriter, page string, data map[string]interface{}) {
	err := templs.ExecuteTemplate(w, page, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Please try letter", http.StatusInternalServerError)
	}
}

func dynamic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = filepath.ToSlash(path) // Ensure cross-platform compatibility
	templateFile := fmt.Sprintf("pages/%s.html", path)

	if ok := pages[templateFile]; !ok {
		if strings.HasSuffix(path, "/") {
			path += "index" // route is like /blog/tennis/
		} else {
			path += "/index" // route is like /blog/tennis
		}
		templateFile = fmt.Sprintf("pages/%s.html", path)
	}

	renderHTML(w, templateFile, nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	renderHTML(w, "pages/index.html", nil)
}
```

### snippet boilerplate app

```go
package main

import (
	"database/sql"
	_ "embed"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var remoteAuth RemoteAuth
var app App

type RemoteAuth struct {
	Username  string
	Password  string
	Session   string
	XSRFToken string
}

type App struct {
	IsProduction     bool
	ReloadFromServer bool
	CodestitchURL    string
}

type Database struct {
	DB     *sql.DB
	DBName string
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

	remoteAuth.Username = os.Getenv("codestitchUsername")
	if remoteAuth.Username == "" {
		log.Fatal("Environment variable codestichUsername is not set")
	}

	remoteAuth.Password = os.Getenv("codestitchPassword")
	if remoteAuth.Password == "" {
		log.Fatal("Environment variable codestichPassword is not set")
	}

	// Retrieve session and XSRF tokens from environment variables
	remoteAuth.Session = os.Getenv("codestitch_session")
	if remoteAuth.Session == "" {
		log.Fatal("Environment variable codestitch_session is not set")
	}

	remoteAuth.XSRFToken = os.Getenv("XSRF_TOKEN")
	if remoteAuth.XSRFToken == "" {
		log.Fatal("Environment variable XSRF_TOKEN is not set")
	}

	app.CodestitchURL = "https://codestitch.app/app/dashboard/catalog/sections/3?perPage=180&page=1"

	flag.BoolVar(&app.IsProduction, "isProduction", false, "set production mode: -isProduction=true")
	flag.BoolVar(&app.ReloadFromServer, "reloadFromServer", false, "set reloadFromServer mode: -reloadFromServer=true")
	flag.Parse()
}

func (d *Database) Init() {
	var err error
	d.DB, err = sql.Open("sqlite3", "file:"+d.DBName+"?cache=shared&mode=rwc&_journal_mode=WAL")
	if err != nil {
		log.Fatalln("Failed to open database: ", err)
	}

	_, err = d.DB.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    `)
	if err != nil {
		d.DB.Close()
		log.Fatalln("Failed to create table: ", err)
	}

	d.DB.SetMaxOpenConns(25)
	d.DB.SetMaxIdleConns(25)
	d.DB.SetConnMaxIdleTime(5 * time.Minute)
	d.DB.SetConnMaxLifetime(2 * time.Hour)
}

// Close the database connection
func (d *Database) Close() {
	if err := d.DB.Close(); err != nil {
		log.Printf("Failed to close database: %v", err)
	} else {
		fmt.Println("Closing database without errors")
	}
}

func main() {
	db := Database{DBName: "codestitch.db"}
	db.Init()
	defer db.Close()
	
	// write logic
}

// getHTMLPage returns the HTML content of a given URL
func getHTMLPage(href string) []byte {
	req, err := http.NewRequest("GET", href, nil)
	if err != nil {
		log.Fatalln(err)
	}
	// Manually set the Cookie header using the values retrieved from your browser.
	// Depending on the site's requirements, you might need to include additional cookies.
	cookieHeader := fmt.Sprintf("codestitch_session=%s; XSRF-TOKEN=%s", remoteAuth.Session, remoteAuth.XSRFToken)
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

	if resp.StatusCode != 200 {
		log.Fatalln("HTTP request failed with status code", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	return body
}

```

### snippet boilerplate app gorm

```go
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	_ "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var remoteAuth RemoteAuth
var app App

type RemoteAuth struct {
	Username  string
	Password  string
	Session   string
	XSRFToken string
}

type App struct {
	IsProduction     bool
	ReloadFromServer bool
	CodestitchURL    string
}

type Page struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	URL      string
	PageHTML string
}

type Component struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	URL      string
	PageHTML string
	CSS      string
	JS       string
	HTML     string
	GoCode   string
}

type Category struct {
	ID    uint `gorm:"primaryKey"`
	Name  string
	Pages []Page `gorm:"many2many:category_pages;"`
}

type CodeStitches struct {
	Categories []Category
	Components []Component
}

type Database struct {
	DB     *gorm.DB
	DBName string
}

func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

	remoteAuth.Username = os.Getenv("codestitchUsername")
	if remoteAuth.Username == "" {
		log.Fatal("Environment variable codestichUsername is not set")
	}

	remoteAuth.Password = os.Getenv("codestitchPassword")
	if remoteAuth.Password == "" {
		log.Fatal("Environment variable codestichPassword is not set")
	}

	// Retrieve session and XSRF tokens from environment variables
	remoteAuth.Session = os.Getenv("codestitch_session")
	if remoteAuth.Session == "" {
		log.Fatal("Environment variable codestitch_session is not set")
	}

	remoteAuth.XSRFToken = os.Getenv("XSRF_TOKEN")
	if remoteAuth.XSRFToken == "" {
		log.Fatal("Environment variable XSRF_TOKEN is not set")
	}

	app.CodestitchURL = "https://codestitch.app/app/dashboard/catalog/sections/3?perPage=180&page=1"

	flag.BoolVar(&app.IsProduction, "isProduction", false, "set production mode: -isProduction=true")
	flag.BoolVar(&app.ReloadFromServer, "reloadFromServer", false, "set reloadFromServer mode: -reloadFromServer=true")
	flag.Parse()
}

func (d *Database) Connect() {
	var err error
	d.DB, err = gorm.Open(sqlite.Open("file:"+d.DBName+"?_cache=shared&mode=rwc&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Get underlying *sql.DB for further configuration
	sqlDB, err := d.DB.DB()
	if err != nil {
		log.Fatalf("Failed to get SQL DB instance: %v", err)
	}

	// Set database connection pooling options
	sqlDB.SetMaxOpenConns(10)           // Max 10 open connections
	sqlDB.SetMaxIdleConns(5)            // Max 5 idle connections
	sqlDB.SetConnMaxLifetime(time.Hour) // Recycle connections every hour

	fmt.Println("Connected to SQLite database:", d.DBName)
}

func (d *Database) Close() {
	sqlDB, err := d.DB.DB()
	if err != nil {
		log.Printf("Error getting SQL DB instance for closing: %v", err)
		return
	}
	sqlDB.Close()
	fmt.Println("Database connection closed.")
}

func (d *Database) ExtractLinksFromHTML(htmlFile []byte) {
	/*

		<ul id="stitch-list">
		    <li class="dropdown">
		        <span class="category category_toggle">E-Commerce</span>
		        <ul class="child_list">
		            <li><a href="https://codestitch.app/app/dashboard/catalog/sections/100">All <span class="cat-options">(23)</span></a></li>
		            <li><a href="https://codestitch.app/app/dashboard/catalog/232">Collections <span class="cat-options">(11)</span></a></li>
		        </ul>
		    </li>
		    <li class="dropdown">
		        <span class="category category_toggle">Buttons</span>
		        <ul class="child_list">
		            <li><a href="https://codestitch.app/app/dashboard/catalog/sections/22">All <span class="cat-options">(11)</span></a></li>
		        </ul>
		    </li>
		</ul>

	*/

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlFile))
	if err != nil {
		log.Fatalln("Error loading HTML:", err)
	}

	doc.Find("li.dropdown").Each(func(i int, s *goquery.Selection) {
		name := s.Find("span.category_toggle").Text()
		fmt.Println("Element:", name)

		// Find sub-items
		s.Find("ul.child_list a").Each(func(j int, a *goquery.Selection) {
			href, exists := a.Attr("href")
			if exists {
				value := a.Find("span.cat-options").Contents().Nodes[0].Data
				fmt.Printf("  - Link: %s | Value: %s\n", href, value)
			}
		})
	})
}

func main() {
	db := &Database{DBName: "codestitch.db"}
	db.Connect()
	defer db.Close()
	
	// write logic
	htmlFile := getHTMLPage(app.CodestitchURL)
}

// getHTMLPage returns the HTML content of a given URL
func getHTMLPage(href string) []byte {
	req, err := http.NewRequest("GET", href, nil)
	if err != nil {
		log.Fatalln(err)
	}
	// Manually set the Cookie header using the values retrieved from your browser.
	// Depending on the site's requirements, you might need to include additional cookies.
	cookieHeader := fmt.Sprintf("codestitch_session=%s; XSRF-TOKEN=%s", remoteAuth.Session, remoteAuth.XSRFToken)
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

	if resp.StatusCode != 200 {
		log.Fatalln("HTTP request failed with status code", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	return body
}

```

### snippet email send

```go
func emailSendLink(email, link string) error {
	// Create a new email - specify the SMTP host:port and auth (if needed)
	mail := mailyak.New("smtp.mail.me.com:587", smtp.PlainAuth("", smtpUser, smtpPass, "smtp.mail.me.com"))

	mail.To(email)
	mail.From(smtpUser)
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

// verifyUserEmail sends a verification email: verifyUserEmail(w, user, "/urlPath")
func verifyUserEmail(w http.ResponseWriter, email, token, urlPath string) (err error) {
	resetLink := fmt.Sprintf(domain+urlPath+"?token=%s", token)
	if isProduction {
		go func() {
			err = emailSendLink(email, resetLink)
			if err != nil {
				setCookie(w, tokenCookieValidate, "", time.Now().Add(-time.Hour))
			}
		}()
	} else {
		logToFileWithCaller(levelInfo, resetLink)
	}
	return err
}
```

### snippet random key generator

```go
func generateKey() []byte {
	randomBytes := make([]byte, 32) // 32 bytes, 256 bit
	numBytesRead, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal("Error generating random key.", err)
	}
	if numBytesRead != 32 {
		log.Fatal("Error generating 32 random bytes for key.")
	}
	return randomBytes
}
```

### snippet random number generator

```go
seed := time.Now().UnixNano()
r := rand.New(rand.NewSource(seed))
randomNumber := r.Intn(100)
```

### snippet sentiment analysis

```go
"github.com/cdipaolo/sentiment"

model, err := sentiment.Restore()
if err != nil {
    panic(err)
}

var analysis *sentiment.Analysis
var text string

// Negative Example
text = "Your mother is an awful lady"
analysis = model.SentimentAnalysis(text, sentiment.English)
if analysis.Score == 1 {
    log.Printf("%s - Score of %d = Positive Sentiment\n", text, analysis.Score)
} else {
    log.Printf("%s - Score of %d = Negative Sentiment\n", text, analysis.Score)
}

// Positive Example
text = "Your mother is a lovely lady"
analysis = model.SentimentAnalysis(text, sentiment.English)
if analysis.Score == 1 {
    log.Printf("%s - Score of %d = Positive Sentiment\n", text, analysis.Score)
} else {
    log.Printf("%s - Score of %d = Negative Sentiment\n", text, analysis.Score)
}
```

### snippet validate password

```go
func checkPasswordStrength(password string) bool {
	if !isProduction {
		return true
	}
	if len(password) < 12 {
		return false
	}
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}
```

### snippet word count

```go
// WordCount function counts the number of occurrences of each word in the given string.
func WordCount(s string) map[string]int {
    // Create a map to store the count of each word.
    wordCount := make(map[string]int)

    // Split the string into words. We consider a word to be a sequence of letters and digits.
    fields := strings.FieldsFunc(s, func(c rune) bool {
        return !unicode.IsLetter(c) && !unicode.IsDigit(c)
    })

    // Increment the count for each word in the map.
    for _, word := range fields {
        wordCount[word]++
    }

    // Return the map with word counts.
    return wordCount
}
```

### snippet turnstile

```go
package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"pocketplate/app/filelog"
	"time"
)

const (
	api_endpoint    = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	default_timeout = 15
)

type turnstile struct {
	SecretKey string
	Timeout   time.Duration
}

type response struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTs time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
}

func (r *response) IsSuccess() bool {
	return r.Success
}

func (r *response) HasErrors() bool {
	return len(r.ErrorCodes) > 0
}

func newTurnstile(secretKey string, timeout int) *turnstile {
	return &turnstile{
		SecretKey: secretKey,
		Timeout:   time.Duration(timeout) * time.Second,
	}
}

func (t *turnstile) verify(responseToken string, remoteIP string) (*response, error) {
	data := url.Values{
		"secret":   {t.SecretKey},
		"response": {responseToken},
	}
	if remoteIP != "" {
		data.Add("remoteip", remoteIP)
	}

	request, err := http.PostForm(api_endpoint, data)
	if err != nil {
		return nil, err
	}
	defer request.Body.Close()

	response := &response{}
	if err := json.NewDecoder(request.Body).Decode(response); err != nil {
		return nil, err
	}

	return response, nil
}

func ValidateTurnstile(w http.ResponseWriter, r *http.Request) (ok bool) {
	// TODO: move secret key to avoid leaks
	validator := newTurnstile("0x4AAAAAAAS-lrqDH1USP4oraJ_rHkgg46c", default_timeout)

	// Get the CAPTCHA token from the 'cf-turnstile-response' form value
	captchaToken := r.FormValue("cf-turnstile-response")

	// Get the user's IP address
	userIP := getRealIP(r)

	// Captcha token received from form value cf-turnstile-response
	// Remote IP isn't required, if you wouldn't pass IP then insert ""
	response, err := validator.verify(captchaToken, userIP)
	if err != nil {
		filelog.Log.Error(err)
		return false
	}

	if response.HasErrors() {
		var errorCodes string
		for _, v := range response.ErrorCodes {
			errorCodes += v + " "
		}
		filelog.Log.Error(fmt.Errorf("errorCodes: %s", errorCodes))
	}

	if !response.IsSuccess() {
		return false
	}

	return true
}

// getRealIP retrieves the real IP address from the request.
func getRealIP(r *http.Request) string {
	// Check for headers that might contain the real IP address
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}
```

### snippet email verify

```go
// verifyUserEmail sends a verification email: verifyUserEmail(w, user, "/urlPath")
func verifyUserEmail(w http.ResponseWriter, email, urlPath string) error {
	resetToken, err := encryptToken(email, []byte(config.Config.SecretKey))
	if err != nil {
		log.Println(err)
		return err
	}

	// Send a password reset email
	resetLink := fmt.Sprintf(config.Config.Domain+urlPath+"?token=%s", resetToken)
	cookies.Set(w, "tokenValidate", resetToken, time.Now().Add(1*time.Hour)) // TODO: insert to verification_tokens

	if config.Config.IsProd {
		go func() {
			if err = emailSendLink(email, resetLink); err != nil {
				log.Println(err)
				cookies.Delete(w, "tokenValidate")
			}
		}()
	} else {
		fmt.Println(resetLink)
	}
	return err
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

func verifyTokens(token1, token2 string) (string, error) {
	email1, err := decryptToken(token1, []byte(config.Config.SecretKey))
	if err != nil {
		return "", err
	}

	email2, err := decryptToken(token2, []byte(config.Config.SecretKey))
	if err != nil {
		return "", err
	}

	if email1 != email2 {
		return "", errors.New("tokens don't match")
	}
	return email1, nil
}
```

### snippet turnstile verify

```go
if ok := captcha.ValidateTurnstile(w, r); !ok {
    http.Error(w, "CAPTCHA failed. Try again.", http.StatusForbidden)
    return
}
```

### snippet binance calculate quantity

```go
// calculateValidQuantity computes valid quantity for a custom USDC amount.
// Args:
//
//	symbol: Trading pair (e.g., "BTCUSDC").
//	moneyStr: Desired USDC amount (e.g., "10.5").
func calculateValidQuantity(client *bc.Client, symbol, moneyStr string) (float64, error) {
	errg, ctx := errgroup.WithContext(context.Background())
	stepSize, minNotional, priceStr := decimal.Decimal{}, decimal.Decimal{}, []*bc.TickerPriceResponse{}

	errg.Go(func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var err error
		// Fetch symbol info (precision, minNotional)
		stepSize, minNotional, err = getSymbolFilters(client, symbol)
		if err != nil {
			return err
		}
		return nil
	})

	errg.Go(func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var err error
		// Fetch latest price
		priceStr, err = marketGetLastPrice(client, symbol)
		if err != nil {
			return err
		}
		return nil
	})

	if err := errg.Wait(); err != nil {
		return 0, err
	}

	// Parse inputs
	money, _ := decimal.NewFromString(moneyStr)
	price, _ := decimal.NewFromString(priceStr[0].Price)
	if money.IsZero() || price.IsZero() {
		return 0, fmt.Errorf("invalid money/price")
	}

	// Calculate quantity and round UP to stepSize precision
	quantity := money.Div(price)
	quantity = adjustToStepSize(quantity, stepSize)

	// Ensure notional ≥ max(minNotional, money)
	minNotionalVal := decimal.Max(minNotional, money)
	if notional := quantity.Mul(price); notional.LessThan(minNotionalVal) {
		return 0, fmt.Errorf("notional too small (need %s, got %s)", minNotionalVal, notional)
	}

	return quantity.InexactFloat64(), nil
}

// getSymbolFilters retrieves precision (stepSize) and minNotional from Binance
func getSymbolFilters(client *bc.Client, symbol string) (stepSize, minNotional decimal.Decimal, err error) {
	res, err := client.NewExchangeInfoService().Symbol(symbol).Do(context.Background())
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("failed to fetch symbol info: %v", err)
	}

	for _, s := range res.Symbols {
		if s.Symbol == symbol {
			for _, filter := range s.Filters {
				// Extract LOT_SIZE (stepSize)
				if filter.FilterType == "LOT_SIZE" {
					stepSize = decimal.RequireFromString(filter.StepSize)
				}
				// Extract MIN_NOTIONAL or NOTIONAL filter
				if filter.FilterType == "MIN_NOTIONAL" || filter.FilterType == "NOTIONAL" {
					minNotional = decimal.RequireFromString(filter.MinNotional)
				}
			}
			return stepSize, minNotional, nil
		}
	}
	return decimal.Zero, decimal.Zero, fmt.Errorf("symbol %s not found", symbol)
}

// adjustToStepSize rounds UP to Binance's allowed stepSize precision
func adjustToStepSize(qty, stepSize decimal.Decimal) decimal.Decimal {
	if stepSize.IsZero() {
		return qty
	}
	// Calculate precision from stepSize (e.g., "0.001" → 3 decimals)
	stepFloat, _ := stepSize.Float64()
	precision := -decimal.NewFromFloat(stepFloat).Exponent()

	// Round up to stepSize multiple (e.g., 0.123456 → 0.124)
	return qty.Div(stepSize).Ceil().Mul(stepSize).Truncate(int32(precision))
}

func parseStrNumToFloat(qtyStr string) (float64, error) {
	qty, _ := decimal.NewFromString(qtyStr)
	if qty.IsZero() {
		return 0, fmt.Errorf("invalid money/price")
	}

	return qty.InexactFloat64(), nil
}

// Function to calculate and force correct float64 format
func calculateTargetSellPrice(buyPrice, quantity, buyFeeRate, sellFeeRate float64) float64 {
	// Convert values to decimal for precision
	buyPriceDec := decimal.NewFromFloat(buyPrice)
	quantityDec := decimal.NewFromFloat(quantity)
	buyFeeRateDec := decimal.NewFromFloat(buyFeeRate)
	sellFeeRateDec := decimal.NewFromFloat(sellFeeRate)

	// Calculate buy fee
	buyFee := buyPriceDec.Mul(quantityDec).Mul(buyFeeRateDec)

	// Calculate target price with 2% profit
	targetPrice := buyPriceDec.Mul(decimal.NewFromFloat(1.02))

	// Estimate sell fee
	sellFee := targetPrice.Mul(quantityDec).Mul(sellFeeRateDec)

	// Final target price including fees
	finalPrice := targetPrice.Add(buyFee.Div(quantityDec)).Add(sellFee.Div(quantityDec)).Round(8)

	// Format as a string to remove scientific notation
	strPrice := finalPrice.String() // Guarantees a fixed decimal format

	// Convert back to float64 properly
	finalFloat, _ := strconv.ParseFloat(strPrice, 64)

	return finalFloat
}

// Function to format float as a proper decimal before passing to Binance API
func formatDecimalForBinance(value float64, precision int) string {
	// Convert to decimal for precision control
	dec := decimal.NewFromFloat(value)

	// Format as a fixed decimal string with correct precision
	return dec.Round(int32(precision)).String() // Keeps trailing zeros
}
```

### snippets server local and production

```go
"golang.org/x/crypto/acme/autocert"

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

if *isProd {
    slog.Info("Starting server with HTTPS", "domain", *domain)
    certManager := &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist(*domain),
        Cache:      autocert.DirCache("certs"),
    }

    go func() {
        httpChallengeServer := &http.Server{
            Addr:         ":80",
            Handler:      certManager.HTTPHandler(nil),
            ReadTimeout:  5 * time.Second,
            WriteTimeout: 5 * time.Second,
            IdleTimeout:  120 * time.Second,
        }
        slog.Info("Starting HTTP challenge server on :80")
        if err := httpChallengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("HTTP challenge server ListenAndServe error", "error", err)
        }
    }()

    httpsServer := &http.Server{
        Addr:         ":443",
        Handler:      finalHandler,
        TLSConfig:    certManager.TLSConfig(),
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    go func() {
        slog.Info("Starting HTTPS server on :443")
        if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("HTTPS server ListenAndServeTLS error", "error", err)
            os.Exit(1)
        }
    }()

    <-ctx.Done()
    stop()

    slog.Info("Shutdown signal received. Shutting down HTTPS server...")
    shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancelShutdown()

    if err := httpsServer.Shutdown(shutdownCtx); err != nil {
        slog.Error("HTTPS server shutdown failed", "error", err)
    }
    slog.Info("HTTPS server gracefully stopped.")

} else {
    slog.Info("Starting server on HTTP", "address", "http://127.0.0.1:8080")
    httpServer := &http.Server{
        Addr:         ":8080",
        Handler:      finalHandler,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    go func() {
        if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("HTTP server ListenAndServe error", "error", err)
            os.Exit(1)
        }
    }()

    <-ctx.Done()
    stop()

    slog.Info("Shutdown signal received. Shutting down HTTP server...")
    shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancelShutdown()

    if err := httpServer.Shutdown(shutdownCtx); err != nil {
        slog.Error("HTTP server shutdown failed", "error", err)
    }
    slog.Info("HTTP server gracefully stopped.")
}
slog.Info("Application exiting.")
```

