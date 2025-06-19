# MyGo Terminal

- Directory: go
- File: MyGo Terminal

## Templates

### termianl pretty print

```go
func printToTerminal() {
	const format = "%v\t%v\t%v\t%v\t%v\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, format, "Title", "Artist", "Album", "Year", "Length")
	fmt.Fprintf(tw, format, "-----", "------", "-----", "----", "------")
	fmt.Fprintf(tw, format, "Song", "Andrei", "Life", "1987", "10min")
	tw.Flush() // calculate column widths and print table
}
```

### terminal ask question

```go
// ssl := doYouWant("ssl")
func doYouWant(option string) (yes bool, err error) {
	answer := ""

	// ask question
	fmt.Printf("Activate %s? (y/N) ", option)

	// get answer
	_, err = fmt.Fscanln(os.Stdin, &answer)
	if err != nil {
		if strings.Contains(err.Error(), "unexpected newline") {
			return false, nil
		} else {
			return false, err
		}
	}

	if answer != "" {
		if strings.ToLower(answer) == "y" {
			yes = true
		}
	}

	return
}
```

### terminal exec command

```go
command := "ls"
c := exec.Command("sh", "-c", command)
o, err := c.Output()
if err != nil {
    return nil, err
}
```

### terminal exec command with syscall

```go
command := "/bin/ls"
env := os.Environ()
syscall.Exec(command, []string{"ls", "-a", "-x"}, env)
```

### terminal flags

```go
strPtr := flag.String("name", "Shiju", "a string")
numbPtr := flag.Int("num", 25, "an int")
boolPtr := flag.Bool("enable", false, "a bool")
var num int
flag.IntVar(&num, "num", 30, "an int")	
// Parse parses flag definitions from the argument list.
flag.Parse()
// Get the values for pointers
fmt.Println("name:", *strPtr)
fmt.Println("num:", *numbPtr)
fmt.Println("enable:", *boolPtr)
// Get the value from a variable
fmt.Println("num:", num)
// Args returns the non-flag command-line arguments.
fmt.Println("arguments:", flag.Args())
```

### terminal read byte

```go
os.Stdin.Read(make([]byte, 1))
```

### terminal read with reader (bufio)

```go
reader := bufio.NewReader(os.Stdin)
for {
  fmt.Printf("Enter some text: ")
  data, err := reader.ReadString('\n')
  if err != nil {
    log.Fatalln(err)
  }
  fmt.Println(data)
}
```

### terminal read with scanner

```go
seen := make(map[string]bool) // a set of strings
input := bufio.NewScanner(os.Stdin)
for input.Scan() {
    line := input.Text()
    if !seen[line] {
        seen[line] = true
        fmt.Println(line)
    }
}

if err := input.Err(); err != nil {
    fmt.Fprintf(os.Stderr, "dedup: %v\n", err)
    os.Exit(1)
}
```

