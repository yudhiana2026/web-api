package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yudhiana/web-api/modules/auth/domain"
	"github.com/yudhiana/web-api/modules/auth/service"
	userDomain "github.com/yudhiana/web-api/modules/user/domain"
	"github.com/yudhiana/web-api/pkg/cookie"
	"github.com/yudhiana/web-api/pkg/security"
)

type AuthHandler struct {
	authService   service.AuthService
	csrfManager   *security.CSRFManager
	cookieManager *cookie.Manager
}

func NewAuthHandler(
	authService service.AuthService,
	csrfManager *security.CSRFManager,
	cookieManager *cookie.Manager,
) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		csrfManager:   csrfManager,
		cookieManager: cookieManager,
	}
}

// Register menangani pembuatan akun pengguna baru
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Payload JSON tidak valid"}`, http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"Email dan password wajib diisi"}`, http.StatusBadRequest)
		return
	}

	user, err := h.authService.Register(r.Context(), req)
	if err != nil {
		if errors.Is(err, userDomain.ErrUserAlreadyExists) {
			http.Error(w, `{"error":"Email sudah terdaftar"}`, http.StatusConflict)
			return
		}
		http.Error(w, `{"error":"Gagal registrasi: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Registrasi berhasil",
		"data":    user,
	})
}

// Login memvalidasi kredensial dan mengatur cookies (HttpOnly, SameSite, Secure)
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Payload JSON tidak valid"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			http.Error(w, `{"error":"Email atau kata sandi tidak valid"}`, http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"error":"Gagal login: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 1. Set Access Token di HttpOnly Cookie
	h.cookieManager.SetAccessTokenCookie(w, resp.AccessToken)

	// 2. Set Refresh Token di HttpOnly Cookie (Path: /api/auth)
	h.cookieManager.SetRefreshTokenCookie(w, resp.RefreshToken)

	// 3. Set CSRF Token di Cookie (HttpOnly: false agar bisa dibaca JS)
	h.cookieManager.SetCSRFCookie(w, resp.CSRFToken)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// RefreshToken menangani Refresh Token Rotation (RTR)
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	rawRefreshToken := ""

	// 1. Baca dari HttpOnly Cookie
	if c, err := r.Cookie(cookie.RefreshTokenCookieName); err == nil && c.Value != "" {
		rawRefreshToken = c.Value
	}

	// 2. Fallback baca dari JSON request body
	if rawRefreshToken == "" {
		var bodyReq struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&bodyReq)
		rawRefreshToken = bodyReq.RefreshToken
	}

	if rawRefreshToken == "" {
		http.Error(w, `{"error":"Refresh token tidak ditemukan"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.authService.RefreshToken(r.Context(), rawRefreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrTokenReused) {
			// PERINGATAN REUSE ATTACK: Bersihkan seluruh cookie dan tolak request
			h.cookieManager.ClearAuthCookies(w)
			http.Error(w, `{"error":"Pelanggaran keamanan: Refresh token reuse terdeteksi. Sesi dicabut."}`, http.StatusForbidden)
			return
		}
		if errors.Is(err, domain.ErrTokenExpired) || errors.Is(err, domain.ErrTokenInvalid) {
			h.cookieManager.ClearAuthCookies(w)
			http.Error(w, `{"error":"Refresh token tidak valid atau kedaluwarsa, silakan login kembali"}`, http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"error":"Gagal memperbarui token: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Perbarui semua cookies dengan pasangan token yang baru (Rotasi)
	h.cookieManager.SetAccessTokenCookie(w, resp.AccessToken)
	h.cookieManager.SetRefreshTokenCookie(w, resp.RefreshToken)
	h.cookieManager.SetCSRFCookie(w, resp.CSRFToken)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Logout mencabut sesi token dan membersihkan semua cookies
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	rawRefreshToken := ""
	if c, err := r.Cookie(cookie.RefreshTokenCookieName); err == nil {
		rawRefreshToken = c.Value
	}

	_ = h.authService.Logout(r.Context(), rawRefreshToken)

	// Bersihkan seluruh cookies
	h.cookieManager.ClearAuthCookies(w)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Logout berhasil, sesi dan cookies telah dibersihkan",
	})
}

// GetCSRFToken mengembalikan token CSRF baru untuk inisialisasi aplikasi frontend
func (h *AuthHandler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	token, err := h.csrfManager.GenerateToken()
	if err != nil {
		http.Error(w, `{"error":"Gagal menghasilkan CSRF token"}`, http.StatusInternalServerError)
		return
	}

	h.cookieManager.SetCSRFCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
	})
}
