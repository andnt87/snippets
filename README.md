# Golang VS Code Snippets Generator

A terminal application written in Go that converts Markdown files into Visual Studio Code snippets. This tool reads Markdown files from a specified directory structure and generates JSON snippet files that can be directly used by VS Code.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [File Structure](#file-structure)
- [Usage](#usage)
- [Parameters](#parameters)
- [Notes and Limitations](#notes-and-limitations)

## Features

- Automatically generate VS Code snippets for various languages.
- Supports a flexible directory structure.
- Copies generated snippet files to your VS Code configuration folder.

## Installation

### First Method (For Go Developers)

1. **Clone the repository.**
2. **Replace or update the Markdown files in the snippets folder as needed.**

Navigate to the project directory and run:
```sh
go run . -snipdir="snippets"
```

Alternatively, install the application:
```sh
go install
```

Then, execute:
```sh
snippets -snipdir="<path_to_your_snippets_folder>"
```

### Second Method (Install as a Global App)

1. Install the application using:
```sh
go install github.com/andnt87/snippets@latest
```
2. Run the app:
```sh
snippets -snipdir="<path_to_your_snippets_folder>"
```

*Note: On Windows, append `.exe` to the executable name (e.g., `snippets.exe`).*

## File Structure

A typical directory setup looks like this:

```
.
├── go.mod
├── main.go
├── README.md
└── snippets
    ├── css
    │   └── MyCSS.md
    ├── go
    │   ├── MyGin.md
    │   ├── MyGo Binance.md
    │   ├── MyGo Concurrency _ Channels.md
    │   ├── MyGo Encode _ Decode.md
    │   ├── MyGo Files _ Directories.md
    │   ├── MyGo Form.md
    │   ├── MyGo Gorm.md
    │   ├── MyGo Imports.md
    │   ├── MyGo Log.md
    │   ├── MyGo.md
    │   ├── MyGo Middlewares.md
    │   ├── MyGo Scrap_Crawl_.md
    │   ├── MyGo Server.md
    │   ├── MyGo Snippets.md
    │   ├── MyGo Sqlite _ Auth.md
    │   ├── MyGo Templates.md
    │   ├── MyGo Terminal.md
    │   ├── MyGo Wails.md
    │   └── MyGo Websocket.md
    ├── html
    │   ├── MyHTML.md
    │   └── MyUtils.md
    └── js
        └── MyJS.md
```

## Usage

The only important thing is that you either run the app from within the snippets directory or provide the correct path using the `-snipdir` parameter. It does not matter what the directory is named (it could be `snippets`, `snippet`, or any other name), as long as the path is correct.

The application processes the Markdown files in your specified folder and generates JSON files. For example, based on the provided directory structure, it will create the following files in the `-snipdir` directory:
- `go.json`
- `css.json`
- `html.json`
- `js.json`

After generating these files, the tool copies them to your VS Code snippets directory.


## Parameters

- **-snipdir**: Specifies the directory containing your snippet Markdown files.  
  - **Default:** Current working directory if not specified.
- **-vsdir**: Specifies the destination directory for the generated VS Code snippet JSON files.
  - **Defaults based on OS:**
    - **Windows:** `%APPDATA%\Code\User\snippets`
    - **Darwin (macOS):** `$HOME/Library/Application Support/Code/User/snippets`
    - **Linux and Others:** `$HOME/.config/Code/User/snippets`

*All parameters are optional but be aware of their default behaviors as described above.*

## Notes and Limitations

- **Overwriting Files:**  
  The generated files (`go.json`, `css.json`, `html.json`, `js.json`) will replace any existing files with the same name in both the source (`-snipdir`) and destination (`-vsdir`) directories.

- **Markdown Parsing Issue:**  
  Markdown code blocks that feature nested triple backticks (```) are not parsed correctly. For example, the following:
  ```go
  /* ```go
  ``` this will produce errors
  ``` */
  ```
  should be avoided or modified to prevent parsing issues.

- **Snippet Folder Requirements:**  
  Ensure that the snippet directory contains only subdirectories whose names match the VS Code snippet language identifiers (e.g., `go`, `css`, `html`, `js`).

- **JetBrains Snippets:**
  The application generate also JetBrain snippets. 

  > I haven't test the generated `xml` files