package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yudhiana/web-api/modules/auth/domain"
	"github.com/yudhiana/web-api/modules/auth/repository"
	userDomain "github.com/yudhiana/web-api/modules/user/domain"
	userService "github.com/yudhiana/web-api/modules/user/service"
	"github.com/yudhiana/web-api/pkg/security"
)

type AuthService interface {
	Register(ctx context.Context, req domain.RegisterRequest) (*userDomain.UserResponse, error)
	Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error)
	RefreshToken(ctx context.Context, rawRefreshToken string) (*domain.AuthResponse, error)
	Logout(ctx context.Context, rawRefreshToken string) error
}

type authService struct {
	userService userService.UserService
	sessionRepo repository.SessionRepository
	jwtManager  *security.JWTManager
	csrfManager *security.CSRFManager
}

func NewAuthService(
	userSvc userService.UserService,
	sessionRepo repository.SessionRepository,
	jwtManager *security.JWTManager,
	csrfManager *security.CSRFManager,
) AuthService {
	return &authService{
		userService: userSvc,
		sessionRepo: sessionRepo,
		jwtManager:  jwtManager,
		csrfManager: csrfManager,
	}
}

// Register mendaftarkan akun baru melalui UserService
func (s *authService) Register(ctx context.Context, req domain.RegisterRequest) (*userDomain.UserResponse, error) {
	return s.userService.CreateUser(ctx, userDomain.CreateUserDTO{
		Email:       req.Email,
		Password:    req.Password,
		Role:        req.Role,
		DisplayName: req.DisplayName,
	})
}

// Login memvalidasi kredensial pengguna, menghasilkan Access Token & Refresh Token (dengan secret terpisah),
// serta CSRF Token dan menyimpan sesi refresh token
func (s *authService) Login(ctx context.Context, req domain.LoginRequest) (*domain.AuthResponse, error) {
	// 1. Verifikasi kredensial via User service
	user, err := s.userService.VerifyCredentials(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, userDomain.ErrUserNotFound) || errors.Is(err, userDomain.ErrInvalidPassword) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// 2. Buat Access Token (HS256 dengan AccessTokenSecret)
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat access token: %w", err)
	}

	// 3. Buat Refresh Token (HS256 dengan RefreshTokenSecret dan JTI unik)
	refreshToken, tokenID, expiresAt, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat refresh token: %w", err)
	}

	// 4. Simpan hash Refresh Token ke database/storage untuk rotasi dan deteksi reuse
	session := &domain.RefreshTokenSession{
		ID:        tokenID,
		UserID:    user.ID,
		TokenHash: s.jwtManager.HashToken(refreshToken),
		Revoked:   false,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	if err := s.sessionRepo.Save(ctx, session); err != nil {
		return nil, fmt.Errorf("gagal menyimpan sesi refresh token: %w", err)
	}

	// 5. Buat CSRF Token menggunakan HMAC dan CSRFSecret
	csrfToken, err := s.csrfManager.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("gagal membuat csrf token: %w", err)
	}

	return &domain.AuthResponse{
		User: userDomain.UserResponse{
			ID:          user.ID,
			Email:       user.Email,
			Role:        user.Role,
			DisplayName: user.DisplayName,
			CreatedAt:   user.CreatedAt,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
		ExpiresIn:    15 * 60, // 15 menit
		TokenType:    "Bearer",
	}, nil
}

// RefreshToken melakukan validasi, rotasi token (Refresh Token Rotation), dan pencegahan reuse attack
func (s *authService) RefreshToken(ctx context.Context, rawRefreshToken string) (*domain.AuthResponse, error) {
	if rawRefreshToken == "" {
		return nil, domain.ErrMissingRefreshToken
	}

	// 1. Validasi tanda tangan kriptografis JWT menggunakan RefreshTokenSecret
	claims, err := s.jwtManager.ValidateRefreshToken(rawRefreshToken)
	if err != nil {
		if errors.Is(err, security.ErrTokenExpired) {
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrTokenInvalid
	}

	// 2. Cari sesi token berdasarkan TokenID (JTI)
	session, err := s.sessionRepo.FindByID(ctx, claims.TokenID)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	// 3. Periksa kedaluwarsa waktu
	if time.Now().After(session.ExpiresAt) {
		return nil, domain.ErrTokenExpired
	}

	// 4. DETEKSI REUSE ATTACK (RFC 6749 / RFC 6819 Security Best Practice):
	// Jika token ini sudah pernah di-revoke sebelumnya, berarti ada aktor yang mencoba
	// menggunakan token yang sudah basi/dicuri! Cabut seluruh sesi aktif milik user ini.
	if session.Revoked {
		_ = s.sessionRepo.RevokeAllForUser(ctx, claims.UserID)
		return nil, domain.ErrTokenReused
	}

	// 5. Verifikasi integritas hash token
	if session.TokenHash != s.jwtManager.HashToken(rawRefreshToken) {
		return nil, domain.ErrTokenInvalid
	}

	// 6. Cabut (Revoke) refresh token lama (Rotation)
	if err := s.sessionRepo.Revoke(ctx, claims.TokenID); err != nil {
		return nil, fmt.Errorf("gagal mencabut token lama: %w", err)
	}

	// 7. Ambil data user terkini
	user, err := s.userService.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, userDomain.ErrUserNotFound
	}

	// 8. Terbitkan Access Token baru
	newAccessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	// 9. Terbitkan Refresh Token baru (Token Rotation)
	newRefreshToken, newTokenID, expiresAt, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	// 10. Simpan sesi token baru
	newSession := &domain.RefreshTokenSession{
		ID:        newTokenID,
		UserID:    user.ID,
		TokenHash: s.jwtManager.HashToken(newRefreshToken),
		Revoked:   false,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	if err := s.sessionRepo.Save(ctx, newSession); err != nil {
		return nil, fmt.Errorf("gagal menyimpan sesi refresh token baru: %w", err)
	}

	// 11. Buat CSRF Token baru
	newCSRFToken, err := s.csrfManager.GenerateToken()
	if err != nil {
		return nil, err
	}

	return &domain.AuthResponse{
		User: userDomain.UserResponse{
			ID:          user.ID,
			Email:       user.Email,
			Role:        user.Role,
			DisplayName: user.DisplayName,
			CreatedAt:   user.CreatedAt,
		},
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		CSRFToken:    newCSRFToken,
		ExpiresIn:    15 * 60,
		TokenType:    "Bearer",
	}, nil
}

// Logout mencabut sesi token pengguna
func (s *authService) Logout(ctx context.Context, rawRefreshToken string) error {
	if rawRefreshToken == "" {
		return nil
	}

	claims, err := s.jwtManager.ValidateRefreshToken(rawRefreshToken)
	if err != nil {
		return nil
	}

	return s.sessionRepo.Revoke(ctx, claims.TokenID)
}
