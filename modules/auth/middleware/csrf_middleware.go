package middleware

import (
	"net/http"

	"github.com/yudhiana/web-api/pkg/cookie"
	"github.com/yudhiana/web-api/pkg/security"
)

type CSRFMiddleware struct {
	csrfManager   *security.CSRFManager
	cookieManager *cookie.Manager
	exemptPaths   map[string]bool
}

func NewCSRFMiddleware(csrfManager *security.CSRFManager, cookieManager *cookie.Manager) *CSRFMiddleware {
	return &CSRFMiddleware{
		csrfManager:   csrfManager,
		cookieManager: cookieManager,
		exemptPaths: map[string]bool{
			"/api/auth/login":    true, // Login publik dikecualikan
			"/api/auth/register": true, // Register publik dikecualikan
			"/api/csrf-token":    true, // Endpoint inisialisasi CSRF
		},
	}
}

// Protect memvalidasi CSRF token pada setiap request mutasi data (POST, PUT, DELETE, PATCH)
func (m *CSRFMiddleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Metode "aman" (GET, HEAD, OPTIONS) tidak memerlukan validasi CSRF
		if isSafeMethod(r.Method) {
			// Jika client belum memiliki cookie csrf_token, otomatis set cookie baru
			if _, err := r.Cookie(cookie.CSRFCookieName); err != nil {
				if token, err := m.csrfManager.GenerateToken(); err == nil {
					m.cookieManager.SetCSRFCookie(w, token)
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		// 2. Periksa pengecualian rute publik
		if m.exemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Baca token dari header 'X-CSRF-Token'
		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" {
			http.Error(w, `{"error":"CSRF validation failed: header X-CSRF-Token tidak ditemukan"}`, http.StatusForbidden)
			return
		}

		// 4. Baca token dari cookie 'csrf_token'
		c, err := r.Cookie(cookie.CSRFCookieName)
		if err != nil || c.Value == "" {
			http.Error(w, `{"error":"CSRF validation failed: cookie csrf_token tidak ditemukan"}`, http.StatusForbidden)
			return
		}

		// 5. Validasi kesesuaian dan cryptographic signature
		if err := m.csrfManager.ValidateToken(headerToken, c.Value); err != nil {
			http.Error(w, `{"error":"CSRF validation failed: `+err.Error()+`"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}
