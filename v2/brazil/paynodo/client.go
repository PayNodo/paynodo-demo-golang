package paynodo

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const DefaultBaseURL = "https://sandbox-api.paynodo.com"

type Client struct {
	BaseURL        string
	MerchantID     string
	MerchantSecret string
	PrivateKeyPEM  []byte
	HTTPClient     *http.Client
	Now            func() time.Time
}

type Response struct {
	Status  int
	Headers http.Header
	Data    any
}

func LoadDotEnv(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "=") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}

func ReadPEM(valueOrPath string) ([]byte, error) {
	if valueOrPath == "" {
		return nil, errors.New("missing PEM value or path")
	}
	if strings.Contains(valueOrPath, "-----BEGIN") {
		return []byte(strings.ReplaceAll(valueOrPath, `\n`, "\n")), nil
	}
	return os.ReadFile(valueOrPath)
}

func ReadJSON(path string) (any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func MinifyJSON(payload any) (string, error) {
	var value any
	switch typed := payload.(type) {
	case string:
		return stripJSONWhitespace(typed), nil
	case []byte:
		return stripJSONWhitespace(string(typed)), nil
	default:
		value = typed
	}
	if value == nil {
		value = map[string]any{}
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func stripJSONWhitespace(input string) string {
	var builder strings.Builder
	builder.Grow(len(input))
	inString := false
	escaped := false

	for _, ch := range input {
		if escaped {
			builder.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			builder.WriteRune(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			builder.WriteRune(ch)
			continue
		}
		if !inString && (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
			continue
		}
		builder.WriteRune(ch)
	}

	return builder.String()
}

func BuildStringToSign(timestamp string, merchantSecret string, payload any) (string, error) {
	body, err := MinifyJSON(payload)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{timestamp, merchantSecret, body}, "|"), nil
}

func SignPayload(timestamp string, merchantSecret string, payload any, privateKeyPEM []byte) (map[string]string, error) {
	stringToSign, err := BuildStringToSign(timestamp, merchantSecret, payload)
	if err != nil {
		return nil, err
	}
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(stringToSign))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	body, err := MinifyJSON(payload)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"signature":    base64.StdEncoding.EncodeToString(signature),
		"stringToSign": stringToSign,
		"body":         body,
	}, nil
}

func SignedHeaders(merchantID string, timestamp string, merchantSecret string, payload any, privateKeyPEM []byte) (map[string]any, error) {
	signed, err := SignPayload(timestamp, merchantSecret, payload, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"headers": map[string]string{
			"Content-Type": "application/json",
			"X-PARTNER-ID": merchantID,
			"X-TIMESTAMP":  timestamp,
			"X-SIGNATURE":  signed["signature"],
		},
		"body":         signed["body"],
		"stringToSign": signed["stringToSign"],
	}, nil
}

func VerifyCallback(rawBody string, timestamp string, signature string, platformPublicKeyPEM []byte) (bool, error) {
	publicKey, err := parsePublicKey(platformPublicKeyPEM)
	if err != nil {
		return false, err
	}
	body, err := MinifyJSON(rawBody)
	if err != nil {
		return false, err
	}
	stringToVerify := strings.Join([]string{timestamp, body}, "|")
	digest := sha256.Sum256([]byte(stringToVerify))
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signatureBytes)
	return err == nil, nil
}

func (c *Client) Request(method string, endpoint string, payload any) (*Response, error) {
	if c.MerchantID == "" {
		return nil, errors.New("merchant id is required")
	}
	if c.MerchantSecret == "" {
		return nil, errors.New("merchant secret is required")
	}
	if len(c.PrivateKeyPEM) == 0 {
		return nil, errors.New("private key is required")
	}

	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	baseURL := strings.TrimRight(c.BaseURL, "/")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	method = strings.ToUpper(method)
	signaturePayload := payload
	if method == http.MethodGet {
		signaturePayload = map[string]any{}
	}
	timestamp := now().UTC().Format(time.RFC3339Nano)
	signed, err := SignedHeaders(c.MerchantID, timestamp, c.MerchantSecret, signaturePayload, c.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	headers := signed["headers"].(map[string]string)
	body := signed["body"].(string)
	var reader io.Reader
	if method != http.MethodGet {
		reader = bytes.NewBufferString(body)
	}

	request, err := http.NewRequest(method, baseURL+endpoint, reader)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var data any
	if len(responseBody) > 0 && json.Unmarshal(responseBody, &data) != nil {
		data = string(responseBody)
	}

	return &Response{
		Status:  response.StatusCode,
		Headers: response.Header,
		Data:    data,
	}, nil
}

func (c *Client) CreatePayIn(payload any) (*Response, error) {
	return c.Request(http.MethodPost, "/v2.0/transaction/pay-in", payload)
}

func (c *Client) CreatePayOut(payload any) (*Response, error) {
	return c.Request(http.MethodPost, "/v2.0/disbursement/pay-out", payload)
}

func (c *Client) InquiryStatus(payload any) (*Response, error) {
	return c.Request(http.MethodPost, "/v2.0/inquiry-status", payload)
}

func (c *Client) InquiryBalance(payload any) (*Response, error) {
	return c.Request(http.MethodPost, "/v2.0/inquiry-balance", payload)
}

func (c *Client) PaymentMethods() (*Response, error) {
	return c.Request(http.MethodGet, "/v2.0/payment-methods", map[string]any{})
}

func parsePrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, expected *rsa.PrivateKey", parsed)
	}
	return key, nil
}

func parsePublicKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, expected *rsa.PublicKey", parsed)
	}
	return key, nil
}
