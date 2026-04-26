package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"paynodo-brazil-v2-demo/paynodo"
)

func main() {
	rootDir := "."
	paynodo.LoadDotEnv(filepath.Join(rootDir, ".env"))

	command := "sign-payin"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	merchantID := getenv("PAYNODO_MERCHANT_ID", "replace_with_merchant_id")
	merchantSecret := getenv("PAYNODO_MERCHANT_SECRET", "replace_with_merchant_secret")

	payIn := payInPayload(merchantID)
	payOut := payOutPayload(merchantID)
	status := statusPayload()
	balance := balancePayload()

	if command == "verify-callback" {
		publicKey, err := paynodo.ReadPEM(getenv("PAYNODO_PLATFORM_PUBLIC_KEY_PEM", getenv("PAYNODO_PLATFORM_PUBLIC_KEY_PATH", filepath.Join(rootDir, "paynodo-public-key.pem"))))
		must(err)
		valid, err := paynodo.VerifyCallback(
			requiredEnv("PAYNODO_CALLBACK_BODY"),
			requiredEnv("PAYNODO_CALLBACK_TIMESTAMP"),
			requiredEnv("PAYNODO_CALLBACK_SIGNATURE"),
			publicKey,
		)
		must(err)
		printJSON(map[string]bool{"valid": valid})
		return
	}

	privateKey, err := paynodo.ReadPEM(getenv("PAYNODO_PRIVATE_KEY_PEM", getenv("PAYNODO_PRIVATE_KEY_PATH", filepath.Join(rootDir, "merchant-private-key.pem"))))
	must(err)

	if command == "sign-payin" {
		timestamp := getenv("PAYNODO_TIMESTAMP", "2026-04-17T16:20:30-03:00")
		signed, err := paynodo.SignedHeaders(merchantID, timestamp, merchantSecret, payIn, privateKey)
		must(err)
		printJSON(signed)
		return
	}

	client := &paynodo.Client{
		BaseURL:        getenv("PAYNODO_BASE_URL", paynodo.DefaultBaseURL),
		MerchantID:     merchantID,
		MerchantSecret: merchantSecret,
		PrivateKeyPEM:  privateKey,
	}

	var response any
	switch command {
	case "payin":
		response, err = client.CreatePayIn(payIn)
	case "payout":
		response, err = client.CreatePayOut(payOut)
	case "status":
		response, err = client.InquiryStatus(status)
	case "balance":
		response, err = client.InquiryBalance(balance)
	case "methods":
		response, err = client.PaymentMethods()
	default:
		fmt.Fprintln(os.Stderr, "Unknown command. Use one of: sign-payin, verify-callback, payin, payout, status, balance, methods")
		os.Exit(1)
	}
	must(err)
	printJSON(response)
}

func payInPayload(merchantID string) string {
	return fmt.Sprintf(
		`{"orderNo":%s,"purpose":%s,"merchant":{"merchantId":%s,"merchantName":%s},"money":{"currency":"BRL","amount":%d},"payer":{"pixAccount":%s},"paymentMethod":%s,"expiryPeriod":%d,"redirectUrl":%s,"callbackUrl":%s}`,
		quote(getenv("PAYNODO_PAYIN_ORDER_NO", "ORDPI2026000001")),
		quote(getenv("PAYNODO_PAYIN_PURPOSE", "customer payment")),
		quote(merchantID),
		quote(getenv("PAYNODO_MERCHANT_NAME", "Integrated Merchant")),
		envInt("PAYNODO_PAYIN_AMOUNT", 12000),
		quote(getenv("PAYNODO_PAYER_PIX_ACCOUNT", "48982488880")),
		quote(getenv("PAYNODO_PAYIN_METHOD", "PIX")),
		envInt("PAYNODO_EXPIRY_PERIOD", 3600),
		quote(getenv("PAYNODO_REDIRECT_URL", "https://merchant.example/return")),
		quote(getenv("PAYNODO_CALLBACK_URL", "https://merchant.example/webhooks/paynodo")),
	)
}

func payOutPayload(merchantID string) string {
	return fmt.Sprintf(
		`{"additionalParam":{},"cashAccount":%s,"receiver":{"taxNumber":%s,"accountName":%s},"merchant":{"merchantId":%s},"money":{"amount":%d,"currency":"BRL"},"orderNo":%s,"paymentMethod":%s,"purpose":%s,"callbackUrl":%s}`,
		quote(getenv("PAYNODO_PAYOUT_CASH_ACCOUNT", "12532481501")),
		quote(getenv("PAYNODO_RECEIVER_TAX_NUMBER", "12345678909")),
		quote(getenv("PAYNODO_RECEIVER_NAME", "Betty")),
		quote(merchantID),
		envInt("PAYNODO_PAYOUT_AMOUNT", 10000),
		quote(getenv("PAYNODO_PAYOUT_ORDER_NO", "ORDPO2026000001")),
		quote(getenv("PAYNODO_PAYOUT_METHOD", "CPF")),
		quote(getenv("PAYNODO_PAYOUT_PURPOSE", "Purpose For Disbursement from API")),
		quote(getenv("PAYNODO_CALLBACK_URL", "https://merchant.example/webhooks/paynodo")),
	)
}

func statusPayload() string {
	return fmt.Sprintf(
		`{"tradeType":%d,"orderNo":%s}`,
		envInt("PAYNODO_STATUS_TRADE_TYPE", 1),
		quote(getenv("PAYNODO_STATUS_ORDER_NO", getenv("PAYNODO_PAYIN_ORDER_NO", "ORDPI2026000001"))),
	)
}

func balancePayload() string {
	return fmt.Sprintf(
		`{"accountNo":%s,"balanceTypes":["BALANCE"]}`,
		quote(getenv("PAYNODO_ACCOUNT_NO", "YOUR_ACCOUNT_NO")),
	)
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	var value int
	if _, err := fmt.Sscanf(getenv(key, fmt.Sprintf("%d", fallback)), "%d", &value); err != nil {
		return fallback
	}
	return value
}

func requiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(key + " is required")
	}
	return value
}

func quote(value string) string {
	encoded, err := json.Marshal(value)
	must(err)
	return string(encoded)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	must(err)
	fmt.Println(string(encoded))
}
