package cookie

import (
	"net/http"
	"time"
)

const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
	CSRFCookieName         = "csrf_token"
)

// Config konfigurasi keamanan cookie
type Config struct {
	Secure          bool          // Hanya kirim melalui HTTPS (true di production)
	Domain          string        // Domain cookie
	AccessTokenTTL  time.Duration // Durasi hidup access token cookie
	RefreshTokenTTL time.Duration // Durasi hidup refresh token cookie
}

// Manager mengelola pembuatan, pengaturan atribut, dan pembersihan cookie HTTP
type Manager struct {
	cfg Config
}

func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// SetAccessTokenCookie mengatur cookie Access Token
// - HttpOnly: true  -> JavaScript (document.cookie) tidak bisa membaca token, mencegah pencurian via XSS
// - SameSite: Lax   -> Mencegah cookie dikirim pada cross-site POST / form submission
// - Secure: true    -> Hanya dikirim melalui koneksi terenkripsi HTTPS (di production)
// - Path: "/"       -> Berlaku untuk seluruh endpoint API
func (m *Manager) SetAccessTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    token,
		Path:     "/",
		Domain:   m.cfg.Domain,
		MaxAge:   int(m.cfg.AccessTokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetRefreshTokenCookie mengatur cookie Refresh Token
// - Path: "/api/auth" -> Dibatasi HANYA ke rute autentikasi. Endpoint data lainnya (seperti /api/users, /api/posts)
//                        tidak akan menerima cookie ini secara otomatis, mengurangi attack surface.
// - SameSite: Strict  -> Browser TIDAK AKAN PERNAH mengirim cookie ini jika request berasal dari situs lain
// - HttpOnly: true    -> Mencegah akses script JavaScript secara mutlak
func (m *Manager) SetRefreshTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    token,
		Path:     "/api/auth",
		Domain:   m.cfg.Domain,
		MaxAge:   int(m.cfg.RefreshTokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// SetCSRFCookie mengatur cookie CSRF Token
// - HttpOnly: false   -> HARUS bernilai FALSE agar JavaScript frontend (React, Vue, Axios)
//                        dapat membaca nilai cookie ini dan memasukkannya ke header 'X-CSRF-Token'
//                        dalam pola Double Submit Cookie.
// - SameSite: Lax     -> Mencegah cross-site request forgery
func (m *Manager) SetCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		Domain:   m.cfg.Domain,
		MaxAge:   int(m.cfg.RefreshTokenTTL.Seconds()),
		HttpOnly: false, // Wajib false untuk CSRF Double Submit
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAuthCookies menghapus semua cookie autentikasi dan CSRF (misalnya saat logout atau pelanggaran keamanan)
func (m *Manager) ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    "",
		Path:     "/",
		Domain:   m.cfg.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     "/api/auth",
		Domain:   m.cfg.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   m.cfg.Domain,
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}
