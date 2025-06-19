# MyGo

- Directory: go
- File: MyGo

## Templates

### mail send link

```go
"github.com/domodwyer/mailyak/v3"

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
```

### hash password bcrypt

```go
"golang.org/x/crypto/bcrypt"

hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### hash sha256

```go
c1 := sha256.Sum256([]byte("x"))
c2 := sha256.Sum256([]byte("X"))
fmt.Printf("%x\n%x\n%t\n%T\n", c1, c2, c1 == c2, c1)
// Output:
// 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
// 4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015
// false
// [32]uint8
```

### struct building from json

```go
type IssuesSearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []*Issue
}

type Issue struct {
	Number    int
	HTMLURL   string `json:"html_url"`
	Title     string
	State     string
	User      *User
	CreatedAt time.Time `json:"created_at"`
	Body      string    // in Markdown format
}

type User struct {
	Login   string
	HTMLURL string `json:"html_url"`
}

/*
{
	"total_count": 123,
	"items":[
		{
			"number": 1,
			"html_url": "https://golang.com",
			"title": "Go",
			"user": {
				"login": "baubabu",
				"html_url": "https://google.com",
				... can be more
			},
			"state": "open",
			"created_at": "021-03-04T13:10:42Z",
			"body": "lorem ipsum...",
			... can be more
		},
		... can be more
	]
}
*/
```

### io pipe (multiple writer)

```go
// the pipe reader and pipe writer implement
// io.Reader and io.Writer
r, w := io.Pipe()

// this needs to be run in a separate go routine
// as it will block waiting for the reader
// close at the end for cleanup
go func() {
  // for now we'll write something basic,
  // this could also be used to encode json
  // base64 encode, etc.
  w.Write([]byte("test\n"))
  w.Close()
}()

if _, err := io.Copy(os.Stdout, r); err != nil {
  log.Fatalln(err)
}
```

### mail read

```go
// an example email message
const msg string = `Date: Thu, 24 Jul 2019 08:00:00 -0700
From: Aaron <fake_sender@example.com>
To: Reader <fake_receiver@example.com>
Subject: Gophercon 2019 is going to be awesome!

Feel free to share my book with others if you're attending.
This recipe can be used to process and parse email information.
`

r := strings.NewReader(msg)
m, err := mail.ReadMessage(r)
if err != nil {
    log.Fatal(err)
}

printHeaderInfo(m.Header)

// after printing the header, dump the body to stdout
if _, err := io.Copy(os.Stdout, m.Body); err != nil {
    log.Fatal(err)
}

// extract header info and print it nicely
func printHeaderInfo(header mail.Header) {
	// this works because we know it's a single address
	// otherwise use ParseAddressList
	toAddress, err := mail.ParseAddress(header.Get("To"))
	if err == nil {
		fmt.Printf("To: %s <%s>\n", toAddress.Name, toAddress.Address)
	}
	fromAddress, err := mail.ParseAddress(header.Get("From"))
	if err == nil {
		fmt.Printf("From: %s <%s>\n", fromAddress.Name, fromAddress.Address)
	}

	fmt.Println("Subject:", header.Get("Subject"))

	// this works for a valid RFC5322 date
	// it does a header.Get("Date"), then a
	// mail.ParseDate(that_result)
	if date, err := header.Date(); err == nil {
		fmt.Println("Date:", date)
	}

	fmt.Println(strings.Repeat("=", 40))
	fmt.Println()
}
```

### os signal

```go
//initialize our channels
signals := make(chan os.Signal)
done := make(chan bool)

//hook them up to the signals lib
signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

//if a signal is caught by this go routine
//it will write to done
go CatchSig(signals, done)

fmt.Println("Press ctrl-c to terminate...")
<-done
fmt.Println("Done!")


// CatchSig sets up a listener for
// SIGINT interrupts
func CatchSig(ch chan os.Signal, done chan bool) {
	// block on waiting for a signal
	sig := <-ch
	// print it when it's received
	fmt.Println("\nsig received:", sig)

	// we can set up handlers for all types of
	// sigs here
	switch sig {
	case syscall.SIGINT:
		fmt.Println("handling a SIGINT now!")
	case syscall.SIGTERM:
		fmt.Println("handling a SIGTERM in an entirely different way!")
	default:
		fmt.Println("unexpected signal received")
	}

	// terminate
	done <- true
}
```

### panic recover

```go
// Panic panics with a divide by zero
func Panic() {
	zero := 0
	a := 1 / zero
	fmt.Println("we'll never get here", a)
}

// Catcher calls Panic
func Recover() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic occurred:", r)
		}
	}()
	Panic()
}
```

### reflect get values and names of a struct

```go
type Student struct {
    Fname  string
    Lname  string
    City   string
    Mobile int64
}

s := Student{"Chetan", "Kumar", "Bangalore", 7777777777}
v := reflect.ValueOf(s)
typeOfS := v.Type()

for i := 0; i< v.NumField(); i++ {
    fmt.Printf("Field: %s\tValue: %v\n", typeOfS.Field(i).Name, v.Field(i).Interface())
}
```

### regex match string

```go
// only letter and numbers. No space, /, # ecc.
match, err := regexp.MatchString("[A-Za-z0-9]+$", projectname)
if err != nil {
    log.Fatalln(err)
}
```

### regex match parameter

```go
var (
	regexPath *regexp.Regexp
)

func init() {
	regexPath = regexp.MustCompile("^/(evenimente)/([a-zA-Z0-9-]+)$")

}

// inside route
if match := regexPath.FindString(r.URL.Path); match != "" {
    fmt.Fprintln(w, path.Base(match))
    return
}
```

### runtime file get path at runtime

```go
_, filename, _, _ := runtime.Caller(0) // get full path of this file
fmt.Println(filename)
```

### runtime os (operating system)

```go
if runtime.GOOS == "windows" {
    fmt.Println("Hello from Windows")
}
```

### runtime check memory

```go
func printStats(mem runtime.MemStats) {
	runtime.ReadMemStats(&mem)
	fmt.Println("mem.Alloc:", mem.Alloc)
	fmt.Println("mem.TotalAlloc:", mem.TotalAlloc)
	fmt.Println("mem.HeapAlloc:", mem.HeapAlloc)
	fmt.Println("mem.NumGC:", mem.NumGC)
	fmt.Println("-----")
}

var mem runtime.MemStats
printStats(mem)
```

### runtime info (compiler, goarch, version, num pcu, num goroutines)

```go
fmt.Print("You are using ", runtime.Compiler, " ")
fmt.Println("on a", runtime.GOARCH, "machine")
fmt.Println("Using Go version", runtime.Version())
fmt.Println("Number of CPUs:", runtime.NumCPU())
fmt.Println("Number of Goroutines:", runtime.NumGoroutine())
```

### time

```go
t := time.Now()
fmt.Println(t.Format(time.RFC3339)) // 2025-02-04T17:10:27+02:00
fmt.Println(t.Format("3:04:01")) // 5:10:02
fmt.Println(t.Format("3:04PM")) // 5:10PM
fmt.Println(t.Format("Mon Jan _2 15:04:05 2006")) // Tue Feb  4 17:10:27 2025
fmt.Println(t.Format("2006-01-02T15:04:05.999999-07:00")) // 2025-02-04T17:10:27.366005+02:00
```

### time how to use

```go
now := time.Now()
fmt.Println(now) // 2025-02-04 17:12:20.723865 +0200 EET m=+0.001601701

ro, err := time.LoadLocation("Europe/Bucharest")
if err != nil {
    log.Fatalln(err)
}

then := time.Date(2009, 11, 17, 20, 34, 58, 651387237, ro)
fmt.Println(then) // 2009-11-17 20:34:58.651387237 +0200 EET

fmt.Println(then.Format("02 January 2006")) // 17 November 2009

fmt.Println(then.Year()) // 2009
fmt.Println(then.Month()) // November
fmt.Println(then.Day()) // 17
fmt.Println(then.Hour()) // 20
fmt.Println(then.Minute()) // 34
fmt.Println(then.Second()) // 58
fmt.Println(then.Nanosecond()) // 651387237
fmt.Println(then.Location()) // 651387237

fmt.Println(then.Weekday()) // Tuesday

fmt.Println(then.Before(now)) // true
fmt.Println(then.After(now)) // false
fmt.Println(then.Equal(now)) // false

diff := now.Sub(then)
fmt.Println(diff) // 133388h37m22.072477763s

fmt.Println(diff.Hours()) // 133388.6227979105
fmt.Println(diff.Minutes()) // 8.00331736787463e+06
fmt.Println(diff.Seconds()) // 4.8019904207247776e+08
fmt.Println(diff.Nanoseconds()) // 480199042072477763

fmt.Println(then.Add(diff)) // 2025-02-04 17:12:20.723865 +0200 EET
fmt.Println(then.Add(-diff)) // 1994-08-31 00:57:36.578909474 +0300 EEST
```

### regex valigate email

```go
var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// isEmailValid checks if the email provided passes the required structure and length.
func isEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}
	return emailRegex.MatchString(e)
}
```

### path normalize for both windows and linux

```go
path = filepath.ToSlash(path)
```

### init get variables from os variables

```go
func init() {
	// Attempt to load the secret key from the environment variable.
	secretKey = os.Getenv("secretKey")
	if secretKey == "" {
		log.Fatal("Environment variable secretKey is not set")
	}

	// Attempt to load the email password from the environment variable.
	emailPassword = os.Getenv("emailPassword")
	if emailPassword == "" {
		log.Fatal("Environment variable emailPassword is not set")
	}

	fmt.Println("Successfully loaded secretKey and emailPassword from environment variables")
}
```

### go build ignore

```go
//go:build ignore
```

### os get environment variable

```go
// Attempt to load the email password from the environment variable.
emailPassword = os.Getenv("emailPassword")
if emailPassword == "" {
    log.Fatal("Environment variable emailPassword is not set")
}

fmt.Println("Successfully loaded secretKey and emailPassword from environment variables")
```

### mail send template with data

```go
package smtp

import (
	"bytes"
	"time"

	"gostart/assets"
	"gostart/internal/funcs"

	"github.com/wneessen/go-mail"

	htmlTemplate "html/template"
	textTemplate "text/template"
)

const defaultTimeout = 10 * time.Second

type Mailer struct {
	client *mail.Client
	from   string
}

func NewMailer(host string, port int, username, password, from string) (*Mailer, error) {
	client, err := mail.NewClient(host, mail.WithTimeout(defaultTimeout), mail.WithSMTPAuth(mail.SMTPAuthLogin), mail.WithPort(port), mail.WithUsername(username), mail.WithPassword(password))
	if err != nil {
		return nil, err
	}

	mailer := &Mailer{
		client: client,
		from:   from,
	}

	return mailer, nil
}

func (m *Mailer) Send(recipient string, data any, patterns ...string) error {
	for i := range patterns {
		patterns[i] = "emails/" + patterns[i]
	}
	msg := mail.NewMsg()

	err := msg.To(recipient)
	if err != nil {
		return err
	}

	err = msg.From(m.from)
	if err != nil {
		return err
	}

	ts, err := textTemplate.New("").Funcs(funcs.TemplateFuncs).ParseFS(assets.EmbeddedFiles, patterns...)
	if err != nil {
		return err
	}

	subject := new(bytes.Buffer)
	err = ts.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}

	msg.Subject(subject.String())

	plainBody := new(bytes.Buffer)
	err = ts.ExecuteTemplate(plainBody, "plainBody", data)
	if err != nil {
		return err
	}

	msg.SetBodyString(mail.TypeTextPlain, plainBody.String())

	if ts.Lookup("htmlBody") != nil {
		ts, err := htmlTemplate.New("").Funcs(funcs.TemplateFuncs).ParseFS(assets.EmbeddedFiles, patterns...)
		if err != nil {
			return err
		}

		htmlBody := new(bytes.Buffer)
		err = ts.ExecuteTemplate(htmlBody, "htmlBody", data)
		if err != nil {
			return err
		}

		msg.AddAlternativeString(mail.TypeTextHTML, htmlBody.String())
	}

	for i := 1; i <= 3; i++ {
		err = m.client.DialAndSend(msg)

		if nil == err {
			return nil
		}

		if i != 3 {
			time.Sleep(2 * time.Second)
		}
	}

	return err
}

/*

package main

import (
	"log"

	"gostart/internal/smtp"
)

func main() {
	// Initialize SMTP settings for the mailer
	host := "smtp.example.com"
	port := 587
	username := "user@example.com"
	password := "password"
	from := "Example <no_reply@example.com>"

	mailer, err := smtp.NewMailer(host, port, username, password, from)
	if err != nil {
		log.Fatalf("Failed to create mailer: %v", err)
	}

	// Data for the email templates. Fields must match the template placeholders.
	data := struct {
		BaseURL       string
		Message       string
		RequestMethod string
		RequestURL    string
		Trace         string
	}{
		BaseURL:       "http://localhost:8080",
		Message:       "An error occurred while processing your request.",
		RequestMethod: "GET",
		RequestURL:    "http://localhost:8080/home",
		Trace:         "example stack trace information",
	}

	// Send email using the template file 'assets/emails/error-notification.tmpl'
	err = mailer.Send("recipient@example.com", data, "error-notification.tmpl")
	if err != nil {
		log.Fatalf("Failed to send email: %v", err)
	}

	log.Println("Email sent successfully.")
}

*/

```

### strings builder

```go
var sb strings.Builder
sb.WriteString("{{define \"" + filepath.Base(filePath) + "\"}}")
```

### sass example

```go
transpiler, _ := libsass.New(libsass.Options{OutputStyle: libsass.CompressedStyle})

	start := time.Now()
	result, _ := transpiler.Execute(`
$font-stack:    Helvetica, sans-serif;
$primary-color: #321;

body {
  font: 100% $font-stack;
  color: $primary-color;
}
`)

	fmt.Println(time.Since(start))
	fmt.Println(result.CSS)
	// Output: body{font:100% Helvetica,sans-serif;color:#333}
```

### cache event (avoid duplicates)

```go
eventCache := make(map[string]time.Time)

now := time.Now()
if lastEventTime, exists := eventCache[event.Name]; exists && now.Sub(lastEventTime) < 100*time.Millisecond {
    continue
}
eventCache[event.Name] = now
```

### errgroup example

```go
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
    priceStr, err = getLatestPrice(client, symbol)
    if err != nil {
        return err
    }
    return nil
})

if err := errg.Wait(); err != nil {
    return 0, err
}
```

### string to float

```go
func parseStrNumToFloat(qtyStr string) (float64, error) {
	qty, _ := decimal.NewFromString(qtyStr)
	if qty.IsZero() {
		return 0, fmt.Errorf("invalid money/price")
	}
	
	return qty.InexactFloat64(), nil
}
```

### envirment get value

```go
apiKey := os.Getenv("BINANCE_PUBLIC")
```

### mod replace

```go
replace github.com/binance/binance-connector-go => github.com/andnt87/binance-connector-go v0.0.0-20250527153907-9d7a2c7a6f22

```

### time format

```go
then.Format("02 January 2006")
```

### decimal from string

```go
money, _ := decimal.NewFromString(moneyStr)
```

### comment for goland (TIP)

```go
//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>
```

### test boilerplate

```go
package main

import (
	"log"
	"os"
	"testing"

	"github.com/asdine/storm/v3"
)

var db *storm.DB // Package-level variable for the DB

// TestMain is executed by the testing package before any tests or benchmarks
// in this package are run.
func TestMain(m *testing.M) {
	// dbPath := "/dev/shm/my_in_memory_storm.db" // Option for RAM disk on Linux
	dbPath := "my_test.db" // Using a local file for the test database

	// Best effort to remove any pre-existing test database file to ensure a clean state.
	// This is helpful if a previous test run was interrupted.
	// We ignore the error here as the file might not exist.
	_ = os.Remove(dbPath)

	var err error
	db, err = storm.Open(dbPath)
	if err != nil {
		// Use log.Printf or fmt.Printf for errors where you want to control the exit yourself.
		log.Printf("CRITICAL: Failed to open test database %s: %v", dbPath, err)
		// No db instance to close if Open failed.
		// The file might or might not have been created by storm.Open before erroring.
		// For simplicity, we exit directly. If storm.Open guarantees file creation on error,
		// an os.Remove(dbPath) could be attempted here.
		os.Exit(1)
	}

	// If storm.Open succeeded, db is valid.
	// We will explicitly close it and remove the file in the teardown phase.

	// Initialize schema
	if err := db.Init(&User{}); err != nil {
		log.Printf("CRITICAL: Failed to initialize User schema for test database %s: %v", dbPath, err)
		// Attempt to clean up since DB was opened.
		_ = db.Close()        // Best effort to close the opened database.
		_ = os.Remove(dbPath) // Best effort to remove the (partially) created db file.
		os.Exit(1)
	}

	// If all setup is successful, run the tests and benchmarks.
	exitCode := m.Run()

	// Teardown phase: This runs after all tests/benchmarks in m.Run() complete.
	// It's crucial to attempt cleanup regardless of test outcomes.
	if err := db.Close(); err != nil {
		log.Printf("Warning: Failed to close test database %s: %v", dbPath, err)
	}
	if err := os.Remove(dbPath); err != nil {
		// This might fail if db.Close() didn't release a lock, or due to permissions, etc.
		log.Printf("Warning: Failed to remove test database file %s: %v", dbPath, err)
	}

	os.Exit(exitCode) // Exit with the status code from m.Run()
}

// Your User struct definition would need to be accessible here.
// (Assuming User struct is defined as in previous contexts or in main.go of package main)
// type User struct {
// 	ID uint `storm:"id,increment"`
// 	// ... other fields
// }

func BenchmarkAll(b *testing.B) {
	var users []User
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := db.All(&users); err != nil {
			b.Fatalf("db.All() failed: %v", err)
		}
	}
}

func BenchmarkAllIndex(b *testing.B) {
	var users []User
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Assuming "ID" is an indexed field in your User struct.
		// If User struct has `storm:"id,increment"`, "ID" is implicitly indexed.
		if err := db.AllByIndex("ID", &users); err != nil {
			b.Fatalf("db.AllByIndex(\"ID\", &users) failed: %v", err)
		}
	}
}

```

### benchmark example

```go
func BenchmarkAll(b *testing.B) {
	// Ensure some data exists for a meaningful benchmark,
	// or benchmark the "no data" case if that's intended.
	// For example, you might add a setup step here or in TestMain
	// to populate the DB if benchmarking retrieval from a populated DB.

	// Example: Add a dummy user if the DB is empty for this benchmark
	// This setup should ideally be outside the b.N loop for accurate benchmarking
	// or done once in TestMain if the data should persist across all benchmarks.
	// For simplicity here, we'll assume the DB might be empty or have data.

	b.ResetTimer() // Reset timer to exclude setup time if any was done before this line
	for i := 0; i < b.N; i++ {
		var users []User // Use var to avoid re-declaration issues in loop if not careful
		if err := db.All(&users); err != nil {
			// In benchmarks, b.Fatal or b.Error is preferred over panic
			// as it integrates better with the testing framework.
			b.Fatalf("db.All() failed: %v", err)
		}
	}
}
```

### err error inline if

```go
err != nil {
    $END$
}
```

### storm init (bolt)

```go
db, err := storm.Open("my.db") // Check for errors when opening
if err != nil {
    log.Fatalf("Failed to open database: %v", err)
}
defer db.Close()

if err := db.Init(&User{}); err != nil {
    panic(err)
}
```

### cache in memory

```go
// Create a cache with a default expiration time of 5 minutes, and which
// purges expired items every 10 minutes
c := cache.New(5*time.Minute, 10*time.Minute)

// Set the value of the key "foo" to "bar", with the default expiration time
c.Set("foo", "bar", cache.DefaultExpiration)
```

### slog setup

```go
func setupLogger(isProd bool) slog.Handler {
	if isProd {
		logFile, err := os.OpenFile("app.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		return slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelInfo,
		})
	}
	return slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
}

// handler := setupLogger(*isProd)
// logger := slog.New(handler)
// slog.SetDefault(logger)
```

### context set

```go
const contextLang contextKeyLang = "lang"
type contextKeyLang string

ctx := context.WithValue(r.Context(), contextLang, targetLang)
next.ServeHTTP(w, r.WithContext(ctx))
```

### parse templates fs

```go
var templ *template.Template

var parseErr error
templ, parseErr = template.New("").ParseFS(f, "templates/*.tmpl", "templates/**/*.tmpl")
if parseErr != nil {
    slog.Error("Failed to parse templates", "error", parseErr)
    os.Exit(1)
}


err := templ.ExecuteTemplate(w, "lang.tmpl", data)
if err != nil {
    slog.Error("Failed to execute template lang.tmpl", "error", err, "lang", lang)
    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
```

### context get

```go
lang := r.Context().Value(contextLang).(string)
```

### middleware concatenation

```go
var finalHandler http.Handler = mux
finalHandler = languageMiddleware(finalHandler)
finalHandler = gzipMiddleware(finalHandler)
finalHandler = recoveryMiddleware(finalHandler)
```

### embedd extract subfolder

```go
//go:embed assets/* templates/*
var f embed.FS

assetsFS, fsErr := fs.Sub(f, "assets")
if fsErr != nil {
    slog.Error("Failed to get sub FS for assets", "error", fsErr)
    os.Exit(1)
}
```

### wr

```go
func $START(w http.ResponseWriter, r *http.Request) {
	$END$
}
```

### path value from url

```go
dynamic := r.PathValue("dynamic")
```

