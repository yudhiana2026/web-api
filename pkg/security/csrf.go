package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrCSRFMissingToken = errors.New("csrf token pada header atau cookie tidak ditemukan")
	ErrCSRFMismatch     = errors.New("csrf token pada header tidak cocok dengan cookie")
	ErrCSRFInvalidToken = errors.New("format csrf token tidak valid")
	ErrCSRFForged       = errors.New("tanda tangan csrf token tidak valid (kemungkinan pemalsuan/tampering)")
)

// CSRFManager mengelola pembuatan dan verifikasi Double Submit CSRF token dengan HMAC signature
type CSRFManager struct {
	secret string
}

func NewCSRFManager(secret string) *CSRFManager {
	return &CSRFManager{secret: secret}
}

// GenerateToken membuat CSRF token bertanda tangan kriptografis
// Format token: <nonce_base64>.<hmac_signature_base64>
func (m *CSRFManager) GenerateToken() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("gagal menghasilkan random bytes untuk CSRF: %w", err)
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
	signature := m.sign(nonceStr)

	return fmt.Sprintf("%s.%s", nonceStr, signature), nil
}

// ValidateToken memvalidasi kesamaan header token dengan cookie token serta tanda tangan HMAC
func (m *CSRFManager) ValidateToken(headerToken, cookieToken string) error {
	if headerToken == "" || cookieToken == "" {
		return ErrCSRFMissingToken
	}

	// 1. Double Submit Check: Pastikan token dari Header persis sama dengan Cookie (constant-time compare)
	if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieToken)) != 1 {
		return ErrCSRFMismatch
	}

	// 2. Format check: <nonce>.<signature>
	parts := strings.Split(cookieToken, ".")
	if len(parts) != 2 {
		return ErrCSRFInvalidToken
	}

	nonceStr := parts[0]
	signatureStr := parts[1]

	// 3. Cryptographic Signature Check: Hitung ulang HMAC dengan CSRF Secret
	expectedSignature := m.sign(nonceStr)
	if subtle.ConstantTimeCompare([]byte(signatureStr), []byte(expectedSignature)) != 1 {
		return ErrCSRFForged
	}

	return nil
}

func (m *CSRFManager) sign(data string) string {
	mac := hmac.New(sha256.New, []byte(m.secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
