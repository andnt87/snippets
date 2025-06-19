# MyGo Wails

- Directory: go
- File: MyGo Wails

## Templates

### wails onshutdown

```go
OnShutdown: func(ctx context.Context) {
    if app.CurrentFile != "" {
        app.RunEncrypt()
    }
},
```

### wails runtime open file

```go
func (a *App) OpenFile() (string, error) {
	file, err := runtime.OpenFileDialog(a.Ctx, runtime.OpenDialogOptions{
		Title: "Choose a file to edit",
	})
	if err != nil {
		return "", err
	}
	if file == "" {
		return "", nil
	}

	a.CurrentFile = file
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	decrypted, err := decryptData(string(data), a.Key)
	if err != nil {
		a.Content = string(data)
	} else {
		a.Content = decrypted
	}

	return a.Content, nil
}
```

### wails import func

```go
import { OpenFile, SaveContent } from '../wailsjs/go/main/App';
```

### wails openfile and save

```go
import './style.css';
import './app.css';

import logo from './assets/images/logo-universal.png';
import { OpenFile, SaveContent } from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
  <img id="logo" class="logo">
  <div class="result" id="status">Choose a file to begin editing:</div>
  <div class="input-box">
    <button class="btn" id="openFileBtn">Choose File</button>
  </div>
  <textarea id="content" rows="20" class="editor" placeholder="File content will appear here..."></textarea>
  <div class="input-box">
    <button class="btn" id="saveFileBtn">Save Changes</button>
  </div>
`;

document.getElementById('logo').src = logo;

const status = document.getElementById('status');
const content = document.getElementById('content');
const openBtn = document.getElementById('openFileBtn');
const saveBtn = document.getElementById('saveFileBtn');

openBtn.addEventListener('click', async () => {
    try {
        const result = await OpenFile();
        if (result !== null && result !== undefined) {
            content.value = result;
            status.innerText = 'File loaded successfully.';
        } else {
            status.innerText = 'No file selected.';
        }
    } catch (err) {
        console.error(err);
        status.innerText = 'Error loading file.';
    }
});

saveBtn.addEventListener('click', async () => {
    try {
        await SaveContent(content.value);
        status.innerText = 'File saved!';
    } catch (err) {
        console.error(err);
        status.innerText = 'Failed to save file.';
    }
});

```

### wails app

```go
type App struct {
	Ctx         context.Context
	CurrentFile string
	Content     string
	Key         []byte
}

func NewApp() *App {
	return &App{
		Key: []byte("forbfwjbfwljibfvfoieubvieufewwdw"),
	}
}
```

### wails save file content

```go
func (a *App) SaveContent(content string) error {
	a.Content = content
	return os.WriteFile(a.CurrentFile, []byte(content), 0644)
}
```

### wails runencrypt

```go
func (a *App) RunEncrypt() {
	if a.CurrentFile == "" || a.Content == "" {
		return
	}
	encrypted, err := encryptData(a.Content, a.Key)
	if err != nil {
		runtime.LogError(a.Ctx, err.Error())
		return
	}
	_ = os.WriteFile(a.CurrentFile, []byte(encrypted), 0644)
}
```

