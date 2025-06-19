# MyGo Binance

- Directory: go
- File: MyGo Binance

## Templates

### binance connect

```go
func binanceConnect() *bc.Client {
	apiKey := os.Getenv("BINANCE_PUBLIC")
	secretKey := os.Getenv("BINANCE_SECRET")
	baseURL := "https://api.binance.com"
	return bc.NewClient(apiKey, secretKey, baseURL)
}

func binanceConnectTest() *bc.Client {
	apiKey := os.Getenv("BINANCE_PUBLIC_TEST")
	secretKey := os.Getenv("BINANCE_SECRET_TEST")
	baseURL := "https://testnet.binance.vision"
	return bc.NewClient(apiKey, secretKey, baseURL)
}
```

