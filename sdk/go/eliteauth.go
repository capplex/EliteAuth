package eliteauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const SigningPublicKey = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ"
const SigningKeyID = "eliteauth-ed25519-2026-01"

type Client struct {
	APIURL               string
	AppID                string
	Version              string
	IntegritySHA256      string
	SDKVersion           string
	MaxServerSkewSeconds int64
	HTTPClient           *http.Client
	publicKey            ed25519.PublicKey
	sessionToken         string
	challenge            string
}

type SessionData struct {
	Token     string `json:"token,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type Result struct {
	Success     bool                   `json:"success"`
	Valid       bool                   `json:"valid,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Session     SessionData            `json:"session,omitempty"`
	Application map[string]interface{} `json:"application,omitempty"`
	License     map[string]interface{} `json:"license,omitempty"`
	ExpiresAt   string                 `json:"expires_at,omitempty"`
	HTTPStatus  int                    `json:"-"`
	RequestID   string                 `json:"-"`
}

type envelope struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type signedPayload struct {
	Protocol   string          `json:"protocol"`
	RequestID  string          `json:"request_id"`
	ServerTime int64           `json:"server_time"`
	Nonce      string          `json:"nonce"`
	Data       json.RawMessage `json:"data"`
}

func NewClient(apiURL, appID, version, integritySHA256 string) (*Client, error) {
	if apiURL == "" || appID == "" || version == "" {
		return nil, errors.New("apiURL, appID and version are required")
	}
	hash, err := normalizeHash(integritySHA256)
	if err != nil {
		return nil, err
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(SigningPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pinned EliteAuth public key")
	}
	return &Client{
		APIURL:               strings.TrimRight(apiURL, "/"),
		AppID:                appID,
		Version:              version,
		IntegritySHA256:      hash,
		SDKVersion:           "go-1.1.0",
		MaxServerSkewSeconds: 300,
		HTTPClient:           &http.Client{Timeout: 15 * time.Second},
		publicKey:            ed25519.PublicKey(publicKey),
	}, nil
}

func (c *Client) Activate(ctx context.Context, licenseKey, hwid string) (*Result, error) {
	nonce, err := randomBase64URL(24)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"app_id":           c.AppID,
		"license_key":      licenseKey,
		"hwid":             hwid,
		"version":          c.Version,
		"sdk_version":      c.SDKVersion,
		"integrity_sha256": nullableString(c.IntegritySHA256),
		"timestamp":        time.Now().Unix(),
		"nonce":            nonce,
	}
	result, err := c.postSigned(ctx, "/v1/license/activate", body, nonce)
	if err != nil {
		return nil, err
	}
	if result.Success {
		if result.Session.Token == "" || result.Session.Challenge == "" {
			return nil, errors.New("signed activation response is missing session state")
		}
		c.sessionToken = result.Session.Token
		c.challenge = result.Session.Challenge
	}
	return result, nil
}

func (c *Client) CheckSession(ctx context.Context, hwid string) (*Result, error) {
	if c.sessionToken == "" || c.challenge == "" {
		return nil, errors.New("call Activate before CheckSession")
	}
	nonce, err := randomBase64URL(24)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"app_id":           c.AppID,
		"session_token":    c.sessionToken,
		"challenge":        c.challenge,
		"hwid":             hwid,
		"sdk_version":      c.SDKVersion,
		"integrity_sha256": nullableString(c.IntegritySHA256),
		"timestamp":        time.Now().Unix(),
		"nonce":            nonce,
	}
	result, err := c.postSigned(ctx, "/v1/session/check", body, nonce)
	if err != nil {
		return nil, err
	}
	if result.Success && result.Valid {
		if result.Session.Challenge == "" {
			return nil, errors.New("signed session response did not rotate the challenge")
		}
		c.challenge = result.Session.Challenge
	}
	return result, nil
}

func (c *Client) ClearSession() {
	c.sessionToken = ""
	c.challenge = ""
}

func (c *Client) postSigned(ctx context.Context, path string, body interface{}, expectedNonce string) (*Result, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	response, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	payload, err := c.verifyEnvelope(raw, expectedNonce)
	if err != nil {
		return nil, err
	}
	var result Result
	if err := json.Unmarshal(payload.Data, &result); err != nil {
		return nil, fmt.Errorf("invalid signed EliteAuth data: %w", err)
	}
	result.HTTPStatus = response.StatusCode
	result.RequestID = payload.RequestID
	return &result, nil
}

func (c *Client) verifyEnvelope(raw []byte, expectedNonce string) (*signedPayload, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("EliteAuth returned invalid JSON")
	}
	if env.KeyID != SigningKeyID || env.Algorithm != "Ed25519" {
		return nil, errors.New("unexpected EliteAuth signing key or algorithm")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, errors.New("invalid EliteAuth signed payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || !ed25519.Verify(c.publicKey, payloadBytes, signature) {
		return nil, errors.New("EliteAuth response signature verification failed")
	}
	var payload signedPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errors.New("invalid verified EliteAuth payload")
	}
	if payload.Protocol != "eliteauth-signed-v1" {
		return nil, errors.New("unsupported EliteAuth signed-response protocol")
	}
	if payload.Nonce != expectedNonce {
		return nil, errors.New("EliteAuth response nonce mismatch")
	}
	if abs64(time.Now().Unix()-payload.ServerTime) > c.MaxServerSkewSeconds {
		return nil, errors.New("EliteAuth response timestamp is outside the allowed window")
	}
	return &payload, nil
}

func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func normalizeHash(value string) (string, error) {
	hash := strings.ToLower(strings.TrimSpace(value))
	if hash == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("integritySHA256 must be a 64-character SHA-256 value")
	}
	return hash, nil
}

func randomBase64URL(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
