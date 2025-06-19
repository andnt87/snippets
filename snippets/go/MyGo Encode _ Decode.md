# MyGo Encode _ Decode

- Directory: go
- File: MyGo Encode _ Decode

## Templates

### base64 encoding and decoding

```go
// using encoder/ decoder
buffer := bytes.Buffer{}

// encode into the buffer
encoder := base64.NewEncoder(base64.StdEncoding, &buffer)

if _, err := encoder.Write([]byte("encoding some other data")); err != nil {
    log.Fatalln(err)
}

// be sure to close
if err := encoder.Close(); err != nil {
    log.Fatalln(err)
}

fmt.Println("Using encoder and StdEncoding: ", buffer.String())

// decoder 
decoder := base64.NewDecoder(base64.StdEncoding, &buffer)
results, err := ioutil.ReadAll(decoder)
if err != nil {
    log.Fatalln(err)
}

fmt.Println("Using decoder and StdEncoding: ", string(results))
```

### env get from file + config

```go
import (
	"github.com/joho/godotenv"
	"log"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}

type config struct {
	baseURL   string
	httpPort  int
	basicAuth struct {
		username       string
		hashedPassword string
	}
	cookie struct {
		secretKey string
	}
	db struct {
		dsn         string
		automigrate bool
	}
	notifications struct {
		email string
	}
	session struct {
		secretKey    string
		oldSecretKey string
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		from     string
	}
}

var cfg config

cfg.baseURL = os.Getenv("BASE_URL")
cfg.httpPort = os.Getenv("HTTP_PORT") // Parse if integer
cfg.basicAuth.username = os.Getenv("BASIC_AUTH_USERNAME")
cfg.basicAuth.hashedPassword = os.Getenv("BASIC_AUTH_HASHED_PASSWORD")
cfg.cookie.secretKey = os.Getenv("COOKIE_SECRET_KEY")
cfg.db.dsn = os.Getenv("DB_DSN")
cfg.db.automigrate = os.Getenv("DB_AUTOMIGRATE") // Parse if boolean
cfg.notifications.email = os.Getenv("NOTIFICATIONS_EMAIL")
cfg.session.secretKey = os.Getenv("SESSION_SECRET_KEY")
cfg.session.oldSecretKey = os.Getenv("SESSION_OLD_SECRET_KEY")
cfg.smtp.host = os.Getenv("SMTP_HOST")
cfg.smtp.port = os.Getenv("SMTP_PORT") // Parse if integer
cfg.smtp.username = os.Getenv("SMTP_USERNAME")
cfg.smtp.password = os.Getenv("SMTP_PASSWORD")
cfg.smtp.from = os.Getenv("SMTP_FROM")
```

### env helpers

```go

func GetString(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	return value
}

func GetInt(key string, defaultValue int) int {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		panic(err)
	}

	return intValue
}

func GetBool(key string, defaultValue bool) bool {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		panic(err)
	}

	return boolValue
}
```

### json decode

```go
var m map[string]string
decoder := json.NewDecoder(file)
err = decoder.Decode(&m)
if err != nil {
    log.Fatalln("Error decoding JSON to map:", err)
}
```

### json encode

```go
var m map[string]string
encoder := json.NewEncoder(file)
err = encoder.Encode(m)
if err != nil {
    log.Fatalln("Error encoding map to JSON:", err)
}
```

### json marshal memory to json

```go
type Employee struct {
	ID                            int
	FirstName, LastName, JobTitle string
}

emp := Employee{
    ID:        100,
    FirstName: "Shiju",
    LastName:  "Varghese",
    JobTitle:  "Architect",
}

// Encoding to JSON
data, err := json.Marshal(emp)
if err != nil {
    fmt.Println(err.Error())
    return
}

jsonStr := string(data)
fmt.Println("The JSON data is:")
fmt.Println(jsonStr)
```

### json unmarshal json to memory

```go
type Employee struct {
	ID                            int
	FirstName, LastName, JobTitle string
}

b := []byte(`{"ID":101,"FirstName":"Irene","LastName":"Rose","JobTitle":"Developer"}`)
var emp1 Employee
// Decoding JSON data to a value of struct type
err := json.Unmarshal(b, &emp1)
if err != nil {
    fmt.Println(err.Error())
    return
}
fmt.Println("The Employee value is:")
fmt.Printf("ID:%d, Name:%s %s, JobTitle:%s", emp1.ID, emp1.FirstName, emp1.LastName, emp1.JobTitle)


```

### encrypt string

```go
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
```

### decrypt string

```go
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

### encrypt int

```go
func encryptTokenId(id uint, secretKey []byte) (string, error) {
	// Convert uint to string safely
	idStr := strconv.FormatUint(uint64(id), 10)
	plaintext := []byte(idStr + "|" + time.Now().Add(1*time.Hour).Format(time.RFC3339))

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", fmt.Errorf("cipher error: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM error: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce error: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}
```

### decrypt int

```go
func decryptTokenId(token string, secretKey []byte) (uint, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("base64 decode error: %w", err)
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return 0, fmt.Errorf("cipher error: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("GCM error: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return 0, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	parts := strings.SplitN(string(plaintext), "|", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid token format")
	}

	id64, err := strconv.ParseUint(parts[0], 10, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid user ID: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid timestamp: %w", err)
	}

	if time.Now().After(expiry) {
		return 0, fmt.Errorf("token expired")
	}

	return uint(id64), nil
}
```

