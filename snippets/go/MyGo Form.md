# MyGo Form

- Directory: go
- File: MyGo Form

## Templates

### form init  decoder and validate

```go
//"github.com/go-playground/validator/v10"
//"github.com/gorilla/schema"

// form processing
var decoder = schema.NewDecoder()
var validate = validator.New()

func init() {
	// This tells the decoder to silently ignore form valuesthat don't correspond to a struct field.
	decoder.IgnoreUnknownKeys(true)
}
```

### form decode and validate

```go
if err := r.ParseForm(); err != nil {
    cookies.FlashSetWithRedirect(w, r, "There was an error processing your request. Please try again.", "/register")
    return
}

// Define an inline struct for signup, with validation tags.
var signupReq = struct {
    Email           string `schema:"email" validate:"required,email"`
    Password        string `schema:"password" validate:"required,min=8"`
    ConfirmPassword string `schema:"confirm_password" validate:"eqfield=Password"`
}{}

// Decode the form values.
if err := decoder.Decode(&signupReq, r.PostForm); err != nil {
    cookies.FlashSetWithRedirect(w, r, "Unexpected error. Please try again later.", "/register")
    return
}

// Validate the fields.
if err := validate.Struct(signupReq); err != nil {
    friendlyErrors := []string{}
    // Loop through each validation error and translate it.
    for _, err := range err.(validator.ValidationErrors) {
        switch err.Field() {
        case "Email":
            friendlyErrors = append(friendlyErrors, "A valid email address is required.")
        case "Password":
            friendlyErrors = append(friendlyErrors, "Your password must be at least 8 characters long.")
        case "ConfirmPassword":
            friendlyErrors = append(friendlyErrors, "The confirmation password must match your password.")
        default:
            friendlyErrors = append(friendlyErrors, "Invalid input for "+err.Field()+".")
        }
    }
    cookies.FlashSetWithRedirect(w, r, strings.Join(friendlyErrors, " "), "/register")
    return
}
```

### form bcrypt compare passwords

```go
// Verify the old password
if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
    return errors.New("old password is incorrect")
}
```

