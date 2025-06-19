# MyUtils

- Directory: html
- File: MyUtils

## Templates

### air windows

```go
# .air.toml (Windows)
root = "."
tmp_dir = "_air"

[build]
# Command to build your application (note the .exe extension)
cmd = "go build -o _air\\main.exe ."
# Name of the resulting binary
bin = "_air\\main.exe"
# File extensions to watch
include_ext = ["go"]
# Directories to exclude from watching
exclude_dir = ["src", ".git", "node_modules", ".idea"]
# Delay between rebuilds in milliseconds
delay = 1000

[color]
main = "yellow"
watcher = "cyan"
build = "green"

```

### env variables for boilerplate linux

```go
# Golang App
export smtpPass="ccnc-baap-aygn-zuao"
export smtpUser="andreinita@icloud.com"
export secretKey="<!cevadestuldesigur32caractere!>"
export tokenKey="altcevadestuldesigur32caractere!"
```

### env file for gostart

```go
BASE_URL=http://localhost:4444
HTTP_PORT=4444
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_HASHED_PASSWORD=$2a$10$jRb2qniNcoCyQM23T59RfeEQUbgdAXfR6S0scynmKfJa5Gj3arGJa
COOKIE_SECRET_KEY=2fjfyjw2of6qgqub2clf5e4lqnzc4ysq
DB_DSN=db.sqlite
DB_AUTOMIGRATE=true
NOTIFICATIONS_EMAIL=
SESSION_SECRET_KEY=j6ska6mu6vqboimnlrumg6shljighxes
SESSION_OLD_SECRET_KEY=
SMTP_HOST=example.smtp.host
SMTP_PORT=25
SMTP_USERNAME=example_username
SMTP_PASSWORD=pa55word
SMTP_FROM=Example Name <no_reply@example.org>
```

