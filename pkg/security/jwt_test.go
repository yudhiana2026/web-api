package security

import (
	"testing"
	"time"
)

func TestJWTManager_DualSecretIsolation(t *testing.T) {
	mgr := NewJWTManager(JWTConfig{
		AccessTokenSecret:  "access-secret-key-min-32-bytes-long!",
		RefreshTokenSecret: "refresh-secret-key-min-32-bytes-long!",
		AccessTokenTTL:     5 * time.Minute,
		RefreshTokenTTL:    1 * time.Hour,
	})

	userID := "user-123"
	email := "test@example.com"
	role := "admin"

	// 1. Generate access token
	accessToken, err := mgr.GenerateAccessToken(userID, email, role)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// 2. Validate access token with AccessTokenSecret -> should succeed
	accessClaims, err := mgr.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if accessClaims.UserID != userID || accessClaims.Email != email || accessClaims.Role != role {
		t.Errorf("Access claims mismatch: %+v", accessClaims)
	}

	// 3. Try to validate access token with RefreshTokenSecret -> MUST FAIL
	if _, err := mgr.ValidateRefreshToken(accessToken); err == nil {
		t.Fatal("Security violation: Access token was successfully verified with RefreshTokenSecret!")
	}

	// 4. Generate refresh token
	refreshToken, tokenID, _, err := mgr.GenerateRefreshToken(userID)
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	// 5. Validate refresh token with RefreshTokenSecret -> should succeed
	refreshClaims, err := mgr.ValidateRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken failed: %v", err)
	}
	if refreshClaims.UserID != userID || refreshClaims.TokenID != tokenID {
		t.Errorf("Refresh claims mismatch: %+v", refreshClaims)
	}

	// 6. Try to validate refresh token with AccessTokenSecret -> MUST FAIL
	if _, err := mgr.ValidateAccessToken(refreshToken); err == nil {
		t.Fatal("Security violation: Refresh token was successfully verified with AccessTokenSecret!")
	}
}

func TestJWTManager_Expiration(t *testing.T) {
	mgr := NewJWTManager(JWTConfig{
		AccessTokenSecret:  "access-secret-key-min-32-bytes-long!",
		RefreshTokenSecret: "refresh-secret-key-min-32-bytes-long!",
		AccessTokenTTL:     -1 * time.Minute, // Sudah expired saat dibuat
		RefreshTokenTTL:    -1 * time.Minute,
	})

	token, err := mgr.GenerateAccessToken("user-1", "user@test.com", "user")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = mgr.ValidateAccessToken(token)
	if err != ErrTokenExpired {
		t.Fatalf("Expected ErrTokenExpired, got: %v", err)
	}
}
