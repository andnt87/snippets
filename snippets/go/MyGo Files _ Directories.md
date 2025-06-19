# MyGo Files _ Directories

- Directory: go
- File: MyGo Files _ Directories

## Templates

### file exist not

```go
if _, err := os.Stat("myfile.txt"); errors.Is(err, fs.ErrNotExist) {
		fmt.Println("myfile.txt does not exist")
	}
```

### file append

```go
f, err := os.OpenFile(cssPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
if err != nil {
    log.Fatal(err)
}
defer f.Close()

if _, err := f.Write([]byte(css)); err != nil {
    log.Fatal(err)
}
```

### file attributes and permission

```go
Use these attributes individually or combined with an OR (|) for second arg of OpenFile().

    e.g. os.O_CREATE|os.O_APPEND, os.O_CREATE|os.O_TRUNC|os.O_WRONLY

    os.O_RDONLY 	// Read only
    os.O_WRONLY 	// Write only
    os.O_RDWR 		// Read and write
    os.O_APPEND 	// Append to end of file
    os.O_CREATE 	// Create is none exist
    os.O_TRUNC 	    // Truncate file when opening

### ile permissions

    0	No permission	                                            ---
    1	Execute permission	                                        --x
    2	Write permission	                                        -w-
    3	Execute and write permission: 1 (execute) + 2 (write) = 3   -wx
    4	Read permission	                                            r--
    5	Read and execute permission: 4 (read) + 1 (execute) = 5	    r-x
    6	Read and write permission: 4 (read) + 2 (write) = 6	        rw-
    7	All permissions: 4 (read) + 2 (write) + 1 (execute) = 7	    rwx
```

### file change permission

```go
// Change perrmissions using Linux style
err := os.Chmod("test.txt", 0777)
if err != nil {
    log.Println(err)
}
```

### file copy content of file to another file

```go
// Open original file
originalFile, err := os.Open("test.txt")
if err != nil {
    log.Fatal(err)
}
defer originalFile.Close()

// Create new file
newFile, err := os.Create("test_copy.txt")
if err != nil {
    log.Fatal(err)
}
defer newFile.Close()

// Copy the bytes to destination from source
bytesWritten, err := io.Copy(newFile, originalFile)
if err != nil {
    log.Fatal(err)
}
log.Printf("Copied %d bytes.", bytesWritten)

// Commit the file contents
// Flushes memory to disk
err = newFile.Sync()
if err != nil {
    log.Fatal(err)
}
```

### file copy from src to dst

```go
// CopyFileFromSrcToDst copies pathSrcFile to pathDstFile
func CopyFileFromSrcToDst(pathSrcFile, pathDstFile string) error {
	// Open original file
	originalFile, err := os.Open(pathSrcFile)
	if err != nil {
		return err
	}
	defer originalFile.Close()

	// Create new file
	newFile, err := os.Create(pathDstFile)
	if err != nil {
		return err
	}
	defer newFile.Close()

	// Copy the bytes to destination from source
	bytesWritten, err := io.Copy(newFile, originalFile)
	if err != nil {
		return err
	}
	log.Printf("Copied %d bytes.", bytesWritten)

	// Commit the file contents
	// Flushes memory to disk
	err = newFile.Sync()
	if err != nil {
		return err
	}
	return nil
}
```

### file cross platform path

```go
examplePath2 := filepath.FromSlash("dir/example")
```

### file delete single

```go
if err := os.Remove("file1.txt"); err != nil {
  return err
}
```

### file dir !exist

```go
if _, err := os.Stat("dirPath"); err != nil {
    fmt.Println("dirPath does not exist")
}
```

### file dir exist

```go
if info, err := os.Stat("mydir"); err == nil && info.IsDir() {
    fmt.Println("mydir exists and is a directory")
}
```

### file embedding([]byte) and write

```go
//go:embed reload.html
var reloadHtmlFile []byte

http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.Write(reloadHtmlFile)
})
```

### file embedding(embed.FS) and static serve embedded directory

```go
//go:embed public/*
var publicFiles embed.FS

// root folder
publicFiles, err := fs.Sub(publicFiles, "public")
if err != nil {
    log.Fatal(err)
}

// public/favicon.ico
http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.FS(publicFiles))))
```

### file exist

```go
if info, err := os.Stat("go.mod"); err == nil && !info.IsDir() {
    fmt.Println("go.mod exists and is a file")
}
```

### file link

```go
// Create a hard link
// You will have two file names that point to the same contents
// Changing the contents of one will change the other
// Deleting/renaming one will not affect the other
err := os.Link("test.txt", "test_also.txt")
if err != nil {
    log.Fatal(err)
}
```

### file open

```go
file, err := os.Open(filePath)
if err != nil {
    log.Fatalln("Error opening file:", err)
}
defer file.Close()
```

### file open (os)

```go
file, err := os.OpenFile("test.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### file quick read (ioutil)

```go
data, err := os.ReadFile("test.txt")
if err != nil {
    log.Fatal(err)
}

log.Printf("Data read: %s\n", data)
```

### file read at least (os)

```go
func FileReadAtLeastNbytes(pathFile string, minBytesToRead int) ([]byte, error) {
	// Open file for reading
	file, err := os.Open(pathFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	minBytes := minBytesToRead
	byteSlice := make([]byte, minBytesToRead*64)
	// io.ReadAtLeast() will return an error if it cannot
	// find at least minBytes to read. It will read as
	// many bytes as byteSlice can hold.
	_, err = io.ReadAtLeast(file, byteSlice, minBytes)
	if err != nil {
		return nil, err
	}
	return byteSlice, err
}
```

### file read exacty

```go
// FileReadExactlyNbytes reads exactly numBytesToRead from pathFile
func FileReadExactlyNbytes(pathFile string, numBytesToRead int) ([]byte, error) {
	// Open file for reading
	file, err := os.Open(pathFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// The file.Read() function will happily read a tiny file in to a large
	// byte slice, but io.ReadFull() will return an
	// error if the file is smaller than the byte slice.
	byteSlice := make([]byte, numBytesToRead)
	_, err = io.ReadFull(file, byteSlice)
	if err != nil {
		return nil, err
	}
	return byteSlice, err
}
```

### file read with scanner (bufio)

```go
input := bufio.NewScanner(os.Stdin)
for input.Scan() {
    //input.Text()
}
if err := input.Err(); err != nil {
    // TODO: scanner error
}
```

### file rename or remove

```go
originalPath := "test.txt"
newPath := "test2.txt"
err := os.Rename(originalPath, newPath)
if err != nil {
    log.Fatal(err)
}
```

### file stat (os)

```go
// Stat returns file info. It will return
// an error if there is no file.
fileInfo, err := os.Stat("test.txt")
if err != nil {
    log.Fatal(err)
}
fmt.Println("File name:", fileInfo.Name())
fmt.Println("Size in bytes:", fileInfo.Size())
fmt.Println("Permissions:", fileInfo.Mode())
fmt.Println("Last modified:", fileInfo.ModTime())
fmt.Println("Is Directory: ", fileInfo.IsDir())
fmt.Printf("System interface type: %T\n", fileInfo.Sys())
fmt.Printf("System info: %+v\n\n", fileInfo.Sys())
```

### file temporary file

```go
// Create a temp dir in the system default temp folder
tempDirPath, err := ioutil.TempDir("", "myTempDir")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Temp dir created:", tempDirPath)

// Create a file in new temp directory
tempFile, err := ioutil.TempFile(tempDirPath, "myTempFile.txt")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Temp file created:", tempFile.Name())

// ... do something with temp file/dir ...

// Close file
err = tempFile.Close()
if err != nil {
    log.Fatal(err)
}

// Delete the resources we created
err = os.Remove(tempFile.Name())
if err != nil {
    log.Fatal(err)
}
err = os.Remove(tempDirPath)
if err != nil {
    log.Fatal(err)
}
```

### file quick write

```go
err := os.WriteFile($1$, $2$, 0644)
if err != nil {
    log.Fatal(err)
}
```

### file write with validation

```go
// FileWriteWithValidation writes content to filePath and validates that the writing was successful
func FileWriteWithValidation(f *os.File, content string) error {
	value := []byte(content)
	count, err := f.Write(value)
	if err != nil {
		return err
	}

	if count != len(value) {
		return errors.New("incorrect length returned from write")
	}
	return nil
}
```

### dir walk (filepath)

```go
var staticFiles []string
err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {  
   if !d.IsDir() {  
      ext := filepath.Ext(d.Name())  
      if ext == ".html" || ext == ".css" || ext == ".js" {  
         // open html file  
         staticFiles = append(staticFiles, path)  
      }  
   }  
   return nil  
})  
  
if err != nil {  
   panic(err)  
}
```

### file os path compatible

```go
pathToEncrypt := filepath.ToSlash(*terminalPath)
```

