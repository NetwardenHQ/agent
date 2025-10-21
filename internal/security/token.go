// Package security provides security utilities for the Netwarden agent
// including token validation, masking, and secure storage.
package security

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
)

const (
	// TokenPrefix is the required prefix for all valid agent tokens
	TokenPrefix = "nw_sk_"

	// TokenMinLength is the minimum length for a valid token
	TokenMinLength = 32

	// TokenMaxLength is the maximum length for a valid token
	TokenMaxLength = 128

	// MaskShowChars is the number of characters to show when masking
	MaskShowChars = 8
)

// TokenValidator handles token validation and security operations
type TokenValidator struct {
	mu            sync.RWMutex
	currentToken  string
	rotationAlert chan string // Channel to notify token rotation
}

// NewTokenValidator creates a new token validator instance
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{
		rotationAlert: make(chan string, 1),
	}
}

// ValidateFormat checks if a token has the correct format
func (tv *TokenValidator) ValidateFormat(token string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if len(token) < TokenMinLength {
		return fmt.Errorf("token too short: minimum length is %d", TokenMinLength)
	}

	if len(token) > TokenMaxLength {
		return fmt.Errorf("token too long: maximum length is %d", TokenMaxLength)
	}

	if !strings.HasPrefix(token, TokenPrefix) {
		return fmt.Errorf("invalid token format: must start with %s", TokenPrefix)
	}

	// Check for valid characters (alphanumeric and underscore after prefix)
	suffix := token[len(TokenPrefix):]
	for i, ch := range suffix {
		if !isValidTokenChar(ch) {
			return fmt.Errorf("invalid character at position %d", len(TokenPrefix)+i)
		}
	}

	return nil
}

// MaskToken returns a masked version of the token for logging
func (tv *TokenValidator) MaskToken(token string) string {
	if token == "" {
		return "***empty***"
	}

	if len(token) <= MaskShowChars {
		return "***masked***"
	}

	// Show first 8 characters followed by asterisks
	return token[:MaskShowChars] + "***"
}

// SetToken securely stores the token in memory
func (tv *TokenValidator) SetToken(token string) error {
	if err := tv.ValidateFormat(token); err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	tv.mu.Lock()
	defer tv.mu.Unlock()

	// Check if token is being rotated
	if tv.currentToken != "" && tv.currentToken != token {
		// Non-blocking send to rotation channel
		select {
		case tv.rotationAlert <- "token_rotated":
		default:
			// Channel full, rotation already pending
		}
	}

	tv.currentToken = token
	return nil
}

// GetToken retrieves the stored token
func (tv *TokenValidator) GetToken() string {
	tv.mu.RLock()
	defer tv.mu.RUnlock()
	return tv.currentToken
}

// CompareTokens performs constant-time comparison of tokens
func (tv *TokenValidator) CompareTokens(token1, token2 string) bool {
	if len(token1) != len(token2) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token1), []byte(token2)) == 1
}

// GetRotationChannel returns the channel for rotation notifications
func (tv *TokenValidator) GetRotationChannel() <-chan string {
	return tv.rotationAlert
}

// ClearToken securely clears the stored token
func (tv *TokenValidator) ClearToken() {
	tv.mu.Lock()
	defer tv.mu.Unlock()

	// Overwrite the token in memory
	if tv.currentToken != "" {
		tokenBytes := []byte(tv.currentToken)
		for i := range tokenBytes {
			tokenBytes[i] = 0
		}
	}

	tv.currentToken = ""
}

// isValidTokenChar checks if a character is valid in a token
func isValidTokenChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_'
}

// TokenStore provides thread-safe token storage with rotation detection
type TokenStore struct {
	validator *TokenValidator
	tenant    string
	mu        sync.RWMutex
}

// NewTokenStore creates a new secure token store
func NewTokenStore() *TokenStore {
	return &TokenStore{
		validator: NewTokenValidator(),
	}
}

// Initialize sets up the token store with initial values
func (ts *TokenStore) Initialize(apiKey, tenantID string) error {
	if err := ts.validator.SetToken(apiKey); err != nil {
		return fmt.Errorf("failed to set API key: %w", err)
	}

	ts.mu.Lock()
	ts.tenant = tenantID
	ts.mu.Unlock()

	return nil
}

// GetAPIKey returns the stored API key
func (ts *TokenStore) GetAPIKey() string {
	return ts.validator.GetToken()
}

// GetTenantID returns the stored tenant ID
func (ts *TokenStore) GetTenantID() string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.tenant
}

// UpdateAPIKey updates the API key and detects rotation
func (ts *TokenStore) UpdateAPIKey(newKey string) error {
	return ts.validator.SetToken(newKey)
}

// GetMaskedKey returns a masked version of the API key for logging
func (ts *TokenStore) GetMaskedKey() string {
	key := ts.validator.GetToken()
	return ts.validator.MaskToken(key)
}

// GetRotationChannel returns the channel for rotation notifications
func (ts *TokenStore) GetRotationChannel() <-chan string {
	return ts.validator.GetRotationChannel()
}

// Clear securely clears all stored tokens
func (ts *TokenStore) Clear() {
	ts.validator.ClearToken()

	ts.mu.Lock()
	ts.tenant = ""
	ts.mu.Unlock()
}
