# MyGo Sqlite _ Auth

- Directory: go
- File: MyGo Sqlite _ Auth

## Templates

### sqlite auth

```go
_ "github.com/mattn/go-sqlite3"

var dbAuth *sql.DB

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func initAuthDB() {
	var err error
	dbAuth, err = sql.Open("sqlite3", "file:auth.db?cache=shared&mode=rwc&_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	_, err = dbAuth.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
	
	dbAuth.SetMaxOpenConns(25)
	dbAuth.SetMaxIdleConns(25)
	dbAuth.SetConnMaxIdleTime(5 * time.Minute)
	dbAuth.SetConnMaxLifetime(2 * time.Hour)
}

func closeAuthDB() {
	err := dbAuth.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Closing database without errors")
}

initAuthDB()
defer closeAuthDB()
```

### sqlite auth exec (create table)

```go
_, err = dbAuth.Exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
`)
```

### sqlite auth exec (INSERT)

```go
_, err = dbAuth.Exec("INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### sqlite auth exec (UPDATE)

```go
_, err = dbAuth.Exec("UPDATE users SET password = ? WHERE email = ?", string(hashedPassword), email)
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### sqlite auth exec (VERIFY)

```go
email := r.FormValue("email")
var exists bool
err := dbAuth.QueryRow("SELECT COUNT(*) > 0 FROM users WHERE email = ?", email).Scan(&exists)
if err != nil || !exists {
    setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
    http.Redirect(w, r, "/change-password", http.StatusSeeOther)
    return
}
```

### sqlite auth query row (example get row by email)

```go
var hashedPassword string
err := dbAuth.QueryRow("SELECT password FROM users WHERE email = ?", user.Email).Scan(&hashedPassword)
if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)) != nil {
    setFlash(w, flashCookie, "Invalid credentials")
    http.Redirect(w, r, "/login", http.StatusSeeOther)
    return
}
```

### sqlite auth compare two password with bcrypt

```go
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
```

### sqlite auth delete

```go
ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_, err = dbAuth.ExecContext(ctx, "DELETE FROM users WHERE email = ?", email)
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### sqlite auth init

```go
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

	// TODO: add verify_tokens table to verify email
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
```

### sqlite auth insert

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_, err = dbAuth.ExecContext(ctx, "INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### sqlite auth select (select password and bcrypt compare)

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
err := dbAuth.QueryRowContext(ctx, "SELECT password, user_type, verified FROM users WHERE email = ?", user.Email).
    Scan(&dbUser.Password, &dbUser.UserType, &dbUser.Verified)
if err != nil || bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)) != nil {
    setFlash(w, flashCookie, "Invalid credentials")
    http.Redirect(w, r, "/login", http.StatusSeeOther)
    return
}
```

### sqlite auth select all

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
rows, err := dbAuth.QueryContext(ctx, "SELECT id, email FROM users")
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
defer rows.Close()

var users []User
for rows.Next() {
    var user User
    if err := rows.Scan(&user.Id, &user.Email); err != nil {
        logToFileWithCaller(levelError, err.Error())
        continue
    }
    users = append(users, user)
}
```

### sqlite auth select check if exist

```go
var exists bool
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
err := dbAuth.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM users WHERE email = ?", email).Scan(&exists)
if err != nil || !exists {
    setFlash(w, flashCookie, "If the email exists, instructions to reset the password have been sent.")
    http.Redirect(w, r, "/change-password", http.StatusSeeOther)
    return
}
```

### sqlite auth transaction

```go
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
        setFlash(w, flashCookie, "An account with the provided email address already exists.")
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
```

### sqlite auth update

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_, err = dbAuth.ExecContext(ctx, "UPDATE users SET password = ? WHERE email = ?", string(hashedPassword), email)
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try later", http.StatusInternalServerError)
    return
}
```

### sqlite delete table content and reset index

```go
_, err := db.Exec("DELETE FROM rackets")
if err != nil {
    log.Fatal("Error deleting existing racket data:", err)
}

// Reset the auto-increment value
_, err = db.Exec("DELETE FROM sqlite_sequence WHERE name='rackets'")
if err != nil {
    log.Fatal("Error resetting auto-increment value:", err)
}
```

