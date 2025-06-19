# MyGo Templates

- Directory: go
- File: MyGo Templates

## Templates

### template html variable

```go
{{$number := .}}
<h1> It is day number {{$number}} of the month </h1>
```

### template html range

```go
<ul>
{{ range . }}
  <li>{{ . }}</li>
{{ end}}
</ul>
```

### template html if

```go
{{ if . }}
  Number is greater than 5!
{{ else }}
  Number is 5 or less!
{{ end }}
```

### template html and

```go
{{if and .User .User.Admin}}
  You are an admin user!
{{else}}
  Access denied!
{{end}}
```

### template html dot change

```go
<div>The dot is {{ . }}</div>
<div>
{{ with "world"}}
  Now the dot is set to {{ . }}
{{ end }}
</div>
<div>The dot is {{ . }} again</div>
```

### template inline html with function

```go
const templ = `Hello {{.Name}} it's {{.T | daysAgo}}`

func daysAgo(t time.Time) string {
	clock, min, sec := t.Clock()
	return fmt.Sprintf("%d:%d:%d\n", clock, min, sec)
}

var report = template.Must(template.New("issuelist").
	Funcs(template.FuncMap{"daysAgo": daysAgo}).
	Parse(templ))
	
data := struct {
    Name string
    T    time.Time
}{
    Name: "Andrei",
    T:    time.Now(),
}
log.Fatalln(report.Execute(os.Stdout, data))
```

### template parse all files and render page (generate html)

```go
var (
	templates     *template.Template
	templatesLock sync.RWMutex
	templateDir   = "app/src"
)

/* Initial load of templates */
if err := loadTemplates(templateDir); err != nil {
    log.Fatal("Failed to load templates:", err)
}

/* index functionality */
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    RenderTemplate(w, "index.html", map[string]interface{}{})
})
	
// Load all templates from the directory dynamically
func loadTemplates(goTemplatesDir string) error {
	files := []string{}

	// Walk through the directory and collect all .html files
	err := filepath.WalkDir(goTemplatesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".html" {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Parse all template files dynamically
	tmpl, err := template.ParseFiles(files...)
	if err != nil {
		return err
	}

	// Safely update the global template reference
	templatesLock.Lock()
	templates = tmpl
	templatesLock.Unlock()

	log.Println("Templates reloaded successfully.")
	return nil
}	

// RenderTemplate safely renders the given template with provided data
func RenderTemplate(w http.ResponseWriter, tmplName string, data map[string]interface{}) {
	templatesLock.RLock()
	defer templatesLock.RUnlock()

	err := templates.ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template execution error: %v", err), http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}
```

### template render inline html

```go
tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Example</title>
</head>
<body>
    <a href="/login">Login</a>
    <a href="/signup">Signup</a>
    <a href="/logout">Logout</a>
    <h1>Authorization Example</h1>
    {{if .FlashMsg}}
            <p style="color: green;">{{.FlashMsg}}</p>
        {{end}}
    {{if .UserEmail}}
        <p>Welcome, {{.UserEmail}}!</p>
    {{else}}
        <p>Welcome, Guest!</p>
    {{end}}
</body>
</html>`

data := map[string]interface{}{
    "UserEmail": userEmail,
    "FlashMsg":  flashMsg,
}

err := RenderTemplateInline(w, tmpl, data)
if err != nil {
    logToFileWithCaller(levelError, err.Error())
    http.Error(w, "Please try letter", http.StatusInternalServerError)
}

func RenderTemplateInline(w http.ResponseWriter, tmpl string, data map[string]interface{}) error {
	tempParsed, err := template.New("").Parse(tmpl)
	if err != nil {
		return err
	}
	err = tempParsed.Execute(w, data)
	if err != nil {
		return err
	}
	return nil
}
```

### template csrf

```go
{{ .csrfField }}
```

