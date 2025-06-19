# MyGo Websocket

- Directory: go
- File: MyGo Websocket

## Templates

### websocket watch for files change inside folder recursively

```go
//go:embed reload.html
var reloadHtmlFile []byte

var (
	upgrader    = websocket.Upgrader{}
	connections = make(map[*websocket.Conn]bool)
	mu          sync.Mutex
	templateDir = "app/src"
)

/* ws */
go watchDirectory(templateDir)
http. HandleFunc("/", func(w http. ResponseWriter, r *http. Request) {
    w.Write([]byte("Hello World!"))
})

http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
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

/* index functionality */
http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.Write(reloadHtmlFile)
})

// Watch for changes in the directory and if there is a change loadTemplates() and notifyClients()
func watchDirectory(directory string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Function to recursively add directories to the watcher
	err = filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			err = watcher.Add(path)
			if err != nil {
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
				if err := templates.Load(); err != nil {
					log.Println("Failed to reload templates:", err)
				}
				ws.NotifyClients()
			}
			// Handle newly created directories
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

// Notify all connected WebSocket clients
func notifyClients() {
	mu.Lock()
	defer mu.Unlock()
	for conn := range connections {
		err := conn.WriteMessage(websocket.TextMessage, []byte("reload"))
		if err != nil {
			log.Println("Error sending message:", err)
			conn.Close()
			delete(connections, conn)
		}
	}
}
```

