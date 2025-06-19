# MyGo Middlewares

- Directory: go
- File: MyGo Middlewares

## Templates

### middleware auth with context

```go
"github.com/golang-jwt/jwt"

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			ctx := context.WithValue(r.Context(), "user_email", "")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Parse and validate the JWT
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err != nil || !token.Valid {
			ctx := context.WithValue(r.Context(), "user_email", "")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Extract the email from the JWT claims
		claims := token.Claims.(jwt.MapClaims)
		userEmail := claims["email"].(string)

		// Attach the user email to the request context for use in handlers
		ctx := context.WithValue(r.Context(), "user_email", userEmail)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

http.HandleFunc("/", authMiddleware(homeHandler))

userEmail, ok := r.Context().Value("user_email").(string)
if !ok {
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

data := map[string]interface{}{
    "UserEmail": userEmail,
}

{{if .UserEmail}}
    <p>Welcome, {{.UserEmail}}!</p>
{{else}}
    <p>Welcome, Guest!</p>
{{end}}
```

### middleware cache static files

```go
package middleware

import "net/http"

func Cache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Cache-Control", "public, max-age=7776000")
		next.ServeHTTP(w, r)
	})
}

http.Handle("/public/", middlewares.Cache(http.StripPrefix("/public/", http.FileServer(http.Dir("static/public")))))
```

### middleware gzip

```go
type GzipMiddleware struct {
	Next http.Handler
}

type gzipResponseWriter struct {
	http.ResponseWriter
	io.Writer
}

type gzipPusherResponseWriter struct {
	gzipResponseWriter
	http.Pusher
}

func (gm *GzipMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if gm.Next == nil {
		gm.Next = http.DefaultServeMux
	}

	encodings := r.Header.Get("Accept-Encoding")
	if !strings.Contains(encodings, "gzip") {
		gm.Next.ServeHTTP(w, r)
		return
	}
	w.Header().Add("Content-Encoding", "gzip")
	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()
	var rw http.ResponseWriter
	if pusher, ok := w.(http.Pusher); ok { // see if original writer implements server push
		rw = gzipPusherResponseWriter{
			gzipResponseWriter: gzipResponseWriter{
				ResponseWriter: w,
				Writer:         gzipWriter,
			},
			Pusher: pusher,
		}
	} else {
		rw = gzipResponseWriter{
			ResponseWriter: w,
			Writer:         gzipWriter,
		}
	}
	gm.Next.ServeHTTP(rw, r)
}

func (grw gzipResponseWriter) Write(data []byte) (int, error) {
	return grw.Writer.Write(data)
}
```

### middleware handle (handler ServeHTTP) with chain

```go
type HelloHandler struct{}

func (h HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello!")
}

func log(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Handler called - %T\n", h)
		h.ServeHTTP(w, r)
	})
}

func protect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// some code to make sure the user is authorized
		h.ServeHTTP(w, r)
	})
}

hello := HelloHandler{}
http.Handle("/hello", protect(log(hello)))
```

### middleware handler func (HandlerFunc) with chain

```go
func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello!")
}

func log(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
		fmt.Println("Handler function called - " + name)
		h(w, r)
	}
}

http.HandleFunc("/hello", log(hello)) 
```

### middleware secure headers

```go
// Custom middleware handler logs user agent
func addSecureHeaders(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Security-Policy", "default-src 'self'")
		w.Header().Add("X-Frame-Options", "SAMEORIGIN")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
		w.Header().Add("Strict-Transport-Security", "max-age=10000, includeSubdomains; preload")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		h(w, r)
	}
}

http.HandleFunc("/", addSecureHeaders(index))
```

### middleware recovery with  slog

```go
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("Panic recovered", "error", err, "path", r.URL.Path)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
```

### middleware gzip simple

```go
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w gzipResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w gzipResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}
```

