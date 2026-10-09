package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("token tidak valid")
	ErrTokenExpired = errors.New("token telah kedaluwarsa")
)

// AccessTokenClaims payload data untuk access token
type AccessTokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims payload data untuk refresh token
type RefreshTokenClaims struct {
	UserID  string `json:"user_id"`
	TokenID string `json:"token_id"` // JTI unik untuk tracking token rotation & revocation
	jwt.RegisteredClaims
}

// JWTConfig konfigurasi secret keys dan masa berlaku token
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
}

// JWTManager menangani pembuatan dan validasi token JWT dengan secret terpisah
type JWTManager struct {
	cfg JWTConfig
}

func NewJWTManager(cfg JWTConfig) *JWTManager {
	return &JWTManager{cfg: cfg}
}

// GenerateAccessToken membuat access token berumur pendek menggunakan AccessTokenSecret
func (m *JWTManager) GenerateAccessToken(userID, email, role string) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "modular-api-auth",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(m.cfg.AccessTokenSecret))
	if err != nil {
		return "", fmt.Errorf("gagal menandatangani access token: %w", err)
	}

	return signedToken, nil
}

// GenerateRefreshToken membuat refresh token berumur panjang dengan JTI unik menggunakan RefreshTokenSecret
func (m *JWTManager) GenerateRefreshToken(userID string) (string, string, time.Time, error) {
	tokenID, err := generateRandomHex(16)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("gagal membuat jti refresh token: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(m.cfg.RefreshTokenTTL)

	claims := RefreshTokenClaims{
		UserID:  userID,
		TokenID: tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID,
			Issuer:    "modular-api-auth",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(m.cfg.RefreshTokenSecret))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("gagal menandatangani refresh token: %w", err)
	}

	return signedToken, tokenID, expiresAt, nil
}

// ValidateAccessToken memvalidasi integritas dan masa berlaku access token menggunakan AccessTokenSecret
func (m *JWTManager) ValidateAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode signing tidak valid: %v", t.Header["alg"])
		}
		return []byte(m.cfg.AccessTokenSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateRefreshToken memvalidasi integritas dan masa berlaku refresh token menggunakan RefreshTokenSecret
func (m *JWTManager) ValidateRefreshToken(tokenStr string) (*RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode signing tidak valid: %v", t.Header["alg"])
		}
		return []byte(m.cfg.RefreshTokenSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// HashToken melakukan SHA-256 hash pada refresh token untuk disimpan di database/in-memory
func (m *JWTManager) HashToken(tokenStr string) string {
	hash := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(hash[:])
}

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
