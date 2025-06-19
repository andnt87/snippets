# MyGo Gorm

- Directory: go
- File: MyGo Gorm

## Templates

### gorm create

```go
type Page struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	Name       string `gorm:"index"`
	URL        string
	HTML       []byte
	CategoryID uint
}

type Category struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Name  string `gorm:"index"`
	Pages []Page
}

if err := d.DB.Create(&category).Error; err != nil {
    log.Println("Error saving category:", err)
}
```

### gorm get all join

```go
type Page struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	Name       string `gorm:"index"`
	URL        string
	HTML       []byte
	CategoryID uint
}

type Category struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Name  string `gorm:"index"`
	Pages []Page
}

var categories []Category
// Retrieve the categories and their pages from the database
err := d.DB.Preload("Pages").Find(&categories).Error
if err != nil {
    return nil, err
}
```

### gorm literal: ID

```go
uint `gorm:"primaryKey;autoIncrement"`
```

### gorm init

```go
// "gorm.io/driver/sqlite"
// "gorm.io/gorm"

type Page struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	Name       string `gorm:"index"`
	URL        string
	HTML       []byte
	CategoryID uint
}

type Category struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Name  string `gorm:"index"`
	Pages []Page
}

type Database struct {
	DB *gorm.DB
}

func (d *Database) Connect() {
	var err error
	d.DB, err = gorm.Open(sqlite.Open("file:codestitch.db?cache=shared&mode=rwc&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to SQLite database: %v", err)
	}

	// Drop existing tables to start fresh
	err = d.DB.Migrator().DropTable(&Category{}, &Page{})
	if err != nil {
		log.Fatalf("Failed to drop existing tables: %v", err)
	}

	// Migrate the schema automatically, create tables, etc.
	err = d.DB.AutoMigrate(&Category{}, &Page{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	fmt.Println("Connected to SQLite database:", "codestitch.db")
}

func (d *Database) Close() {
	// SQLite doesn't require explicit closing with GORM.
	// The connection will be closed automatically when the program ends.
	// Retrieve the underlying SQL DB connection.
	db, err := d.DB.DB()
	if err != nil {
		log.Println("Error getting database connection:", err)
		return
	}

	// Attempt to close the connection.
	if err = db.Close(); err != nil {
		log.Println("Error closing database connection:", err)
	} else {
		fmt.Println("Database connection closed.")
	}
}
```

### gorm transaction

```go
type Page struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	Name       string `gorm:"index"`
	URL        string
	HTML       []byte
	CategoryID uint
}

type Category struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Name  string `gorm:"index"`
	Pages []Page
}

for _, category := range categories {
    // Save category and its pages in a single transaction
    d.DB.Transaction(func(tx *gorm.DB) error {
        if err := tx.Create(&category).Error; err != nil {
            return err
        }
        return nil
    })
}
```

### gorm literal: unique, not null

```go
`gorm:"unique;not null"`
```

### gorm update value/values

```go
if err := auth.Model(&User{}).
    Where("id = ?", id).
    Update("verified", true).Error; err != nil {
    return err
}
```

### gorm delete

```go
if err = auth.Delete(&User{}, userID).Error; err != nil {
    return
}
```

### gor get struct by email

```go
var user User
if err := auth.Where("email = ?", email).First(&user).Error; err != nil {
    return err
}
```

### gorm get struct by id

```go
var user User
if err := auth.First(&user, id).Error; err != nil {
    return "", err
}
```

### gorm get all structs

```go
if err = auth.Find(&users).Error; err != nil {
    return nil, err
}
```

### gorm create struct

```go
if err := auth.Create(&user).Error; err != nil {
    return User{}, err
}
```

