package middleware

import (
	"net/http"
	"strings"

	"github.com/yudhiana/web-api/pkg/cookie"
	"github.com/yudhiana/web-api/pkg/security"
)

type AuthMiddleware struct {
	jwtManager *security.JWTManager
}

func NewAuthMiddleware(jwtManager *security.JWTManager) *AuthMiddleware {
	return &AuthMiddleware{jwtManager: jwtManager}
}

// RequireAuth memverifikasi token akses dari HttpOnly Cookie atau Authorization Header
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ""

		// 1. Coba baca dari HttpOnly Cookie 'access_token' (Metode utama browser)
		if c, err := r.Cookie(cookie.AccessTokenCookieName); err == nil && c.Value != "" {
			tokenStr = c.Value
		}

		// 2. Fallback: Baca dari Header Authorization: Bearer <token> (Untuk mobile / curl / external clients)
		if tokenStr == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenStr == "" {
			http.Error(w, `{"error":"Autentikasi diperlukan: access token tidak ditemukan"}`, http.StatusUnauthorized)
			return
		}

		// 3. Validasi token dengan AccessTokenSecret
		claims, err := m.jwtManager.ValidateAccessToken(tokenStr)
		if err != nil {
			status := http.StatusUnauthorized
			errMsg := "Token akses tidak valid atau kedaluwarsa"
			if err == security.ErrTokenExpired {
				errMsg = "Token akses telah kedaluwarsa, silakan lakukan refresh token"
			}
			http.Error(w, `{"error":"`+errMsg+`"}`, status)
			return
		}

		// 4. Simpan claims ke dalam context request
		ctx := security.SetClaimsContext(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
