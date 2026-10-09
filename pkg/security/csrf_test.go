package security

import (
	"strings"
	"testing"
)

func TestCSRFManager(t *testing.T) {
	secret := "csrf-secret-key-min-32-bytes-long!"
	mgr := NewCSRFManager(secret)

	// 1. Generate valid token
	token, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// 2. Validate valid match
	if err := mgr.ValidateToken(token, token); err != nil {
		t.Fatalf("ValidateToken failed on matching tokens: %v", err)
	}

	// 3. Mismatched header and cookie
	anotherToken, _ := mgr.GenerateToken()
	if err := mgr.ValidateToken(token, anotherToken); err != ErrCSRFMismatch {
		t.Fatalf("Expected ErrCSRFMismatch, got: %v", err)
	}

	// 4. Forged / Tampered signature
	parts := strings.Split(token, ".")
	tamperedToken := parts[0] + ".tampered_signature"
	if err := mgr.ValidateToken(tamperedToken, tamperedToken); err != ErrCSRFForged {
		t.Fatalf("Expected ErrCSRFForged, got: %v", err)
	}

	// 5. Empty tokens
	if err := mgr.ValidateToken("", token); err != ErrCSRFMissingToken {
		t.Fatalf("Expected ErrCSRFMissingToken, got: %v", err)
	}
}
