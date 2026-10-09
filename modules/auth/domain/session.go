package domain

import (
	"errors"
	"time"

	userDomain "github.com/yudhiana/web-api/modules/user/domain"
)

var (
	ErrInvalidCredentials = errors.New("email atau kata sandi tidak valid")
	ErrTokenExpired        = errors.New("token telah kedaluwarsa")
	ErrTokenInvalid        = errors.New("token tidak valid")
	ErrTokenRevoked        = errors.New("token telah dicabut")
	ErrTokenReused         = errors.New("peringatan keamanan: refresh token terdeteksi digunakan ulang (reuse attempt)")
	ErrMissingRefreshToken = errors.New("refresh token tidak ditemukan")
)

// RefreshTokenSession merepresentasikan status sesi token yang tersimpan di penyimpanan data
type RefreshTokenSession struct {
	ID        string    `json:"id"`         // JTI token
	UserID    string    `json:"user_id"`    // ID pengguna
	TokenHash string    `json:"token_hash"` // SHA-256 hash dari refresh token
	Revoked   bool      `json:"revoked"`    // Status pencabutan
	ExpiresAt time.Time `json:"expires_at"` // Waktu kedaluwarsa
	CreatedAt time.Time `json:"created_at"` // Waktu pembuatan
}

// LoginRequest request payload login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest request payload registrasi
type RegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

// AuthResponse response payload setelah autentikasi berhasil
type AuthResponse struct {
	User         userDomain.UserResponse `json:"user"`
	AccessToken  string                  `json:"access_token,omitempty"`
	RefreshToken string                  `json:"refresh_token,omitempty"`
	CSRFToken    string                  `json:"csrf_token"`
	ExpiresIn    int64                   `json:"expires_in"` // Durasi access token dalam detik
	TokenType    string                  `json:"token_type"`
}
