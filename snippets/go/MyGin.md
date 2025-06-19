# MyGin

- Directory: go
- File: MyGin

## Templates

### gin init

```go
g := gin.New()        // Creates a new Gin router without the default logger
g.Use(gin.Recovery()) // Adds only the recovery middleware
gin.SetMode(gin.ReleaseMode)
```

### gin form set memory

```go
// Set a lower memory limit for multipart forms (default is 32 MiB)
g.MaxMultipartMemory = 8 << 20 // 8 MiB
```

### gin get embedded folders

```go
//go:embed assets/* templates/*
var f embed.FS

// example: /public/assets/images/example.png
assets, _ := fs.Sub(f, "assets")
g.StaticFS("/public", http.FS(assets))

g.GET("favicon.ico", func(c *gin.Context) {
    file, _ := f.ReadFile("assets/favicon.ico")
    c.Data(http.StatusOK, "image/x-icon", file)
})
```

### gin favicon

```go
g.GET("favicon.ico", func(c *gin.Context) {
    file, _ := f.ReadFile("assets/favicon.ico")
    c.Data(http.StatusOK, "image/x-icon", file)
})
```

### gin handler html

```go
g.GET("/", func(c *gin.Context) {
    c.HTML(http.StatusOK, "index.tmpl", gin.H{
        "title": "Main website",
    })
})
```

### gin basic auth on group

```go
authorized := g.Group("/auth")
authorized.Use(gin.BasicAuth(gin.Accounts{
    "foo":  "bar",
    "manu": "123",
}))

authorized.GET("admin", func(c *gin.Context) {
    c.String(http.StatusOK, "admin")
})

/* example curl for /admin with basicauth header
	   Zm9vOmJhcg== is base64("foo:bar")

		curl -X POST \
	  	http://localhost:8080/auth/admin \
	  	-H 'authorization: Basic Zm9vOmJhcg==' \
	  	-H 'content-type: application/json' \
	  	-d '{"value":"bar"}'
	*/
	authorized.POST("admin", func(c *gin.Context) {
		user := c.MustGet(gin.AuthUserKey).(string)
		c.String(http.StatusOK, "user: "+user)
	})
```

### gin https

```go
log.Fatal(autotls.RunWithContext(ctx, g, domain...))

```

### gin handler POST save form

```go
g.POST("/upload", func(c *gin.Context) {
    // single file
    file, _ := c.FormFile("file")
    log.Println(file.Filename)

    // Upload the file to specific dst.
    log.Println(c.SaveUploadedFile(file, "./files/"+file.Filename))

    c.String(http.StatusOK, fmt.Sprintf("'%s' uploaded!", file.Filename))
})
```

### gin middleware (cookie validate example)

```go
func CookieTool() gin.HandlerFunc {
  return func(c *gin.Context) {
    // Get cookie
    if cookie, err := c.Cookie("label"); err == nil {
      if cookie == "ok" {
        c.Next()
        return
      }
    }

    // Cookie verification failed
    c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden with no cookie"})
    c.Abort()
  }
}

route.GET("/home", CookieTool(), func(c *gin.Context) {
c.JSON(200, gin.H{"data": "Your home page"})
})
```

### gin handler with middleware example

```go
route.GET("/home", CookieTool(), func(c *gin.Context) {
    c.JSON(200, gin.H{"data": "Your home page"})
})
```

### gin validate custom and bind

```go
// "github.com/gin-gonic/gin/binding"
// "github.com/go-playground/validator/v10"

// Booking contains binded and validated data.
type Booking struct {
	CheckIn  time.Time `form:"check_in" binding:"required,bookabledate" time_format:"2006-01-02"`
	CheckOut time.Time `form:"check_out" binding:"required,gtfield=CheckIn" time_format:"2006-01-02"`
}

var bookableDate validator.Func = func(fl validator.FieldLevel) bool {
	date, ok := fl.Field().Interface().(time.Time)
	if ok {
		today := time.Now()
		if today.After(date) {
			return false
		}
	}
	return true
}

if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
    v.RegisterValidation("bookabledate", bookableDate)
}

func getBookable(c *gin.Context) {
	var b Booking
	if err := c.ShouldBindWith(&b, binding.Query); err == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Booking dates are valid!"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}
```

### gin bind file (upload)

```go
type BindFile struct {
	Name  string                `form:"name" binding:"required"`
	Email string                `form:"email" binding:"required"`
	File  *multipart.FileHeader `form:"file" binding:"required"`
}

/*
<h1>Bind file with fields</h1>
<form action="/upload" method="post" enctype="multipart/form-data">
    Name: <input type="text" name="name"><br>
    Email: <input type="email" name="email"><br>
    File: <input type="file" name="file"><br><br>
    <input type="submit" value="Submit">
</form>
*/

router.POST("/upload", func(c *gin.Context) {
    var bindFile BindFile

    // Bind file
    if err := c.ShouldBind(&bindFile); err != nil {
        c.String(http.StatusBadRequest, fmt.Sprintf("err: %s", err.Error()))
        return
    }

    // Save uploaded file
    file := bindFile.File
    dst := filepath.Base(file.Filename)
    if err := c.SaveUploadedFile(file, dst); err != nil {
        c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
        return
    }

    c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully with fields name=%s and email=%s.", file.Filename, bindFile.Name, bindFile.Email))
})
```

### gin push

```go
if pusher := c.Writer.Pusher(); pusher != nil {
    // use pusher.Push() to do server push
    if err := pusher.Push("/assets/app.js", nil); err != nil {
        log.Printf("Failed to push: %v", err)
    }
}
```

### gin multiple servers

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

var errg errgroup.Group

func router01() http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(
			http.StatusOK,
			gin.H{
				"code":  http.StatusOK,
				"error": "Welcome server 01",
			},
		)
	})

	return e
}

func router02() http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(
			http.StatusOK,
			gin.H{
				"code":  http.StatusOK,
				"error": "Welcome server 02",
			},
		)
	})

	return e
}

func main() {
	server01 := &http.Server{
		Addr:         ":8080",
		Handler:      router01(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":8081",
		Handler:      router02(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errg.Go(func() error {
		return server01.ListenAndServe()
	})

	errg.Go(func() error {
		return server02.ListenAndServe()
	})

	if err := errg.Wait(); err != nil {
		log.Fatal(err)
	}
}
```

### gin middleware security

```go
// Setup Security Headers
router.Use(func(c *gin.Context) {
    if c.Request.Host != expectedHost {
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid host header"})
        return
    }
    c.Header("X-Frame-Options", "DENY")
    c.Header("Content-Security-Policy", "default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';")
    c.Header("X-XSS-Protection", "1; mode=block")
    c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    c.Header("Referrer-Policy", "strict-origin")
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("Permissions-Policy", "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()")
    c.Next()
})
```

### gin add func template

```go
router.SetFuncMap(template.FuncMap{
    "formatAsDate": formatAsDate,
})

func formatAsDate(t time.Time) string {
	year, month, day := t.Date()
	return fmt.Sprintf("%d%02d/%02d", year, month, day)
}
```

### gin upload multiple filess

```go
router.POST("/upload", func(c *gin.Context) {
    name := c.PostForm("name")
    email := c.PostForm("email")

    // Multipart form
    form, err := c.MultipartForm()
    if err != nil {
        c.String(http.StatusBadRequest, "get form err: %s", err.Error())
        return
    }
    files := form.File["files"]

    for _, file := range files {
        filename := filepath.Base(file.Filename)
        if err := c.SaveUploadedFile(file, filename); err != nil {
            c.String(http.StatusBadRequest, "upload file err: %s", err.Error())
            return
        }
    }

    c.String(http.StatusOK, "Uploaded successfully %d files with fields name=%s and email=%s.", len(files), name, email)
})

/*
<h1>Upload multiple files with fields</h1>

<form action="/upload" method="post" enctype="multipart/form-data">
    Name: <input type="text" name="name"><br>
    Email: <input type="email" name="email"><br>
    Files: <input type="file" name="files" multiple><br><br>
    <input type="submit" value="Submit">
</form>
*/
```

