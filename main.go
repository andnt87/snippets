package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	blue   = "\033[34m"
	reset  = "\033[0m"
)

var (
	snipDir = flag.String("snipdir", "", "Directory to store snippets")
	vsDir   = flag.String("vsdir", "", "Directory to store VS Code snippets, defaults to the current directory")
)

type Snippet struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

func init() {
	flag.Parse()

	if *snipDir == "" {
		*snipDir, _ = os.Getwd()
	} else {
		*snipDir, _ = filepath.Abs(*snipDir)
	}

	if *vsDir == "" {
		switch runtime.GOOS {
		case "windows":
			*vsDir = filepath.Join(os.Getenv("APPDATA"), "Code", "User", "snippets")
		case "darwin":
			*vsDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Code", "User", "snippets")
		default:
			*vsDir = filepath.Join(os.Getenv("HOME"), ".config", "Code", "User", "snippets")
		}
	}

	// check if the snippet directory exists
	dirs := []string{*snipDir, *vsDir}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			log.Fatalf("Error accessing snippet directory %s: %v", *snipDir, err)
		}
	}

	// list all files in the snippet directory
	files, err := os.ReadDir(*snipDir)
	if err != nil {
		log.Fatalf("Error reading snippet directory %s: %v", *snipDir, err)
	}
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".md" {
			// Use ANSI escape codes for colors and add emoji for clarity
			fmt.Printf("%s❌ Snippet directory must include only directories%s\n", red, reset)
			fmt.Printf("%sℹ️  Directory names must correspond to the snippet file extensions, e.g., 'go' for Go snippets%s\n", blue, reset)
			fmt.Printf("%s⚠️  Found file: %s%s\n", yellow, file.Name(), reset)
			os.Exit(1)
		}
	}

}

func main() {
	var snippets = map[string][]Snippet{}
	err := filepath.WalkDir(*snipDir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			ext := filepath.Ext(d.Name())
			if ext == ".md" {
				file, err := os.Open(path)
				if err != nil {
					fmt.Println("Error opening file:", red, err, reset)
					return filepath.SkipDir
				}
				defer file.Close()

				snippet := Snippet{}
				start := false
				code := ""

				input := bufio.NewScanner(file)
				for input.Scan() {
					line := input.Text()
					if len(line) > 0 && strings.Contains(line, "###") {
						snippet.Name = strings.TrimSpace(strings.TrimPrefix(line, "###"))
					}

					if start {
						if strings.Contains(line, "```") {
							start = !start
							snippet.Body = code
							dirName := filepath.Base(filepath.Dir(path))
							snippets[dirName] = append(snippets[dirName], snippet)
							code = ""
							continue
						}

						code += line + "\n"
					}

					if len(line) > 0 && strings.Contains(line, "```") {
						start = !start
						continue
					}
				}
				if err := input.Err(); err != nil {
					log.Fatalln("Error reading file:", red, err, reset)
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalln("Error walking through snippet directory:", red, err, reset)
	}

	// Build JSON for each snippet file (language)
	for n, s := range snippets {

		// Create JetBrains snippet file in XML format (Live Templates)
		jbFilePath := filepath.Join(*snipDir, n+"_jetbrains.xml")
		var builder strings.Builder
		builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		builder.WriteString(fmt.Sprintf(`<templateSet group="%s">`+"\n", n))

		snippetsJSON := map[string]interface{}{}
		for _, ss := range s {
			// vscode
			snippetsJSON[ss.Name] = map[string]interface{}{
				"body":        []string{ss.Body},
				"description": "",
				"prefix":      ss.Name,
			}

			// jetbrains
			// Escape special XML characters in the name and body
			nameEscaped := html.EscapeString(ss.Name)
			bodyEscaped := html.EscapeString(ss.Body)
			builder.WriteString(fmt.Sprintf(`  <template name="%s" value="%s" description="" toReformat="true" toShortenFQNames="true">`+"\n", nameEscaped, bodyEscaped))
			builder.WriteString("    <context>\n")
			builder.WriteString(`      <option name="OTHER" value="true"/>` + "\n")
			builder.WriteString("    </context>\n")
			builder.WriteString("  </template>\n")
		}

		// vscode
		data, err := json.MarshalIndent(snippetsJSON, "", "  ")
		if err != nil {
			log.Println("Error marshalling JSON for", n, ":", err)
			continue
		}
		filePath := filepath.Join(*snipDir, n+".json")
		err = os.WriteFile(filePath, data, 0644)
		if err != nil {
			log.Fatalln("Error creating snippet file", filePath, err)
		}

		// copy file to vsdir
		vsFilePath := filepath.Join(*vsDir, n+".json")
		err = os.WriteFile(vsFilePath, data, 0644)
		if err != nil {
			log.Fatalln("Error copying snippet file to VS Code directory", vsFilePath, err)
		}

		fmt.Println(green, "Successfully created snippet for", n, reset)

		// jetbrains
		builder.WriteString("</templateSet>\n")
		err = os.WriteFile(jbFilePath, []byte(builder.String()), 0644)
		if err != nil {
			log.Fatalln("Error creating JetBrains snippet file", jbFilePath, err)
		}
		fmt.Println(green, "Successfully created JetBrains snippet for", n, reset)
	}
}
