package cookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCookieManager(t *testing.T) {
	mgr := NewManager(Config{
		Secure:          true,
		Domain:          "example.com",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})

	w := httptest.NewRecorder()

	mgr.SetAccessTokenCookie(w, "access-token-xyz")
	mgr.SetRefreshTokenCookie(w, "refresh-token-xyz")
	mgr.SetCSRFCookie(w, "csrf-token-xyz")

	cookies := w.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// 1. Verify Access Token Cookie
	act, exists := cookieMap[AccessTokenCookieName]
	if !exists {
		t.Fatal("AccessTokenCookieName missing")
	}
	if !act.HttpOnly {
		t.Error("AccessTokenCookie must have HttpOnly = true")
	}
	if act.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite=Lax, got %v", act.SameSite)
	}
	if !act.Secure {
		t.Error("Expected Secure = true")
	}
	if act.Path != "/" {
		t.Errorf("Expected Path='/', got '%s'", act.Path)
	}

	// 2. Verify Refresh Token Cookie
	rft, exists := cookieMap[RefreshTokenCookieName]
	if !exists {
		t.Fatal("RefreshTokenCookieName missing")
	}
	if !rft.HttpOnly {
		t.Error("RefreshTokenCookie must have HttpOnly = true")
	}
	if rft.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite=Strict, got %v", rft.SameSite)
	}
	if rft.Path != "/api/auth" {
		t.Errorf("Expected Path='/api/auth', got '%s'", rft.Path)
	}

	// 3. Verify CSRF Cookie
	csrf, exists := cookieMap[CSRFCookieName]
	if !exists {
		t.Fatal("CSRFCookieName missing")
	}
	if csrf.HttpOnly {
		t.Error("CSRFCookie must have HttpOnly = false so JS can read it for Double Submit")
	}

	// 4. Verify ClearAuthCookies
	clearW := httptest.NewRecorder()
	mgr.ClearAuthCookies(clearW)
	clearCookies := clearW.Result().Cookies()
	for _, c := range clearCookies {
		if c.MaxAge != -1 {
			t.Errorf("Cleared cookie %s must have MaxAge=-1, got %d", c.Name, c.MaxAge)
		}
		if c.Value != "" {
			t.Errorf("Cleared cookie %s must have empty value", c.Name)
		}
	}
}
