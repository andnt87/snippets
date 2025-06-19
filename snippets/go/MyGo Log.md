# MyGo Log

- Directory: go
- File: MyGo Log

## Templates

### log set flags

```go
log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
```

### log slog with multiple writers and line number

```go
// NewLog creates and returns a new slog.Logger instance along with a cleanup function.
// The cleanup must be called when the application is shutting down to close the log file.
func NewLog(production bool) (logger *slog.Logger, cleanup func(), err error) {
	var logFile *os.File
	logFile, err = os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}

	cleanup = func() {
		if err := logFile.Close(); err != nil {
			log.Printf("Error closing log file: %v", err)
		}
	}

	opts := &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true, // 👈 This line enables source info (file:line)
	}

	if production {
		logger = slog.New(slog.NewTextHandler(logFile, opts))
	} else {
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		multiHandler := slog.NewTextHandler(multiWriter, opts)
		logger = slog.New(multiHandler)
	}
	return
}
```

### log to memory

```go
// we'll configure the logger to write
// to a bytes.Buffer
buf := bytes.Buffer{}

// second argument is the prefix last argument is about options
// you combine them with a logical or.
logger := log.New(&buf, "logger: ", log.Lshortfile|log.Ldate)
logger.Println("test")
logger.SetPrefix("new logger: ")
logger.Printf("you can also add args(%v) and use Fatalln to log and crash", true)

fmt.Println(buf.String())
```

### log with caller

```go
func logWithCaller(msg string) {
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		log.Println("Failed to get caller info")
		return
	}
	funcName := runtime.FuncForPC(pc).Name()
	log.Printf("[%s:%d %s] %s\n", file, line, funcName, msg)
}
```

### log with multiple writers and line numbers

```go
// NewLog creates and returns a new *log.Logger instance and a cleanup function.
// Logs are written to both app.log and stdout unless production is true.
func NewLog(production bool) (logger *log.Logger, cleanup func(), err error) {
	var logFile *os.File
	logFile, err = os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, err
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
```

