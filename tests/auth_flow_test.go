package tests

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yudhiana/web-api/config"
	"github.com/yudhiana/web-api/modules/auth"
	"github.com/yudhiana/web-api/modules/user"
	"github.com/yudhiana/web-api/pkg/cookie"
	"github.com/yudhiana/web-api/pkg/security"
)

func setupTestApp() http.Handler {
	cfg := &config.Config{
		AccessTokenSecret:  "test-super-secret-access-token-key-32-chars!",
		RefreshTokenSecret: "test-super-secret-refresh-token-key-32-chars!",
		CSRFSecret:         "test-super-secret-csrf-token-key-32-chars!",
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    7 * 24 * time.Hour,
		CookieSecure:       false,
		CookieDomain:       "",
	}

	cookieMgr := cookie.NewManager(cookie.Config{
		Secure:          cfg.CookieSecure,
		Domain:          cfg.CookieDomain,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
	})

	jwtMgr := security.NewJWTManager(security.JWTConfig{
		AccessTokenSecret:  cfg.AccessTokenSecret,
		RefreshTokenSecret: cfg.RefreshTokenSecret,
		AccessTokenTTL:     cfg.AccessTokenTTL,
		RefreshTokenTTL:    cfg.RefreshTokenTTL,
	})

	csrfMgr := security.NewCSRFManager(cfg.CSRFSecret)

	userMod := user.NewModule()
	authMod := auth.NewModule(cfg, userMod.Service, cookieMgr, jwtMgr, csrfMgr)

	mux := http.NewServeMux()
	authMod.RegisterRoutes(mux)
	userMod.RegisterRoutes(mux, authMod.AuthMiddleware.RequireAuth)

	return authMod.CSRFMiddleware.Protect(mux)
}

func TestEndToEndAuthFlow(t *testing.T) {
	app := setupTestApp()

	// 1. Registrasi Pengguna
	regPayload := `{"email":"budi@example.com","password":"password123","display_name":"Budi Santoso","role":"user"}`
	regReq := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(regPayload))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	app.ServeHTTP(regRec, regReq)

	if regRec.Code != http.StatusCreated {
		t.Fatalf("Registrasi gagal, status: %d, body: %s", regRec.Code, regRec.Body.String())
	}

	// 2. Login Pengguna
	loginPayload := `{"email":"budi@example.com","password":"password123"}`
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginPayload))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	app.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login gagal, status: %d, body: %s", loginRec.Code, loginRec.Body.String())
	}

	// Verifikasi Cookie Atribut (HttpOnly, SameSite, MaxAge)
	cookies := loginRec.Result().Cookies()
	var accessTokenCookie, refreshTokenCookie, csrfTokenCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case cookie.AccessTokenCookieName:
			accessTokenCookie = c
		case cookie.RefreshTokenCookieName:
			refreshTokenCookie = c
		case cookie.CSRFCookieName:
			csrfTokenCookie = c
		}
	}

	if accessTokenCookie == nil {
		t.Fatal("Cookie access_token tidak ditemukan")
	}
	if !accessTokenCookie.HttpOnly {
		t.Errorf("access_token HARUS memiliki HttpOnly=true untuk mencegah XSS")
	}
	if accessTokenCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("access_token diharapkan SameSite=Lax, didapat %v", accessTokenCookie.SameSite)
	}

	if refreshTokenCookie == nil {
		t.Fatal("Cookie refresh_token tidak ditemukan")
	}
	if !refreshTokenCookie.HttpOnly {
		t.Errorf("refresh_token HARUS memiliki HttpOnly=true untuk mencegah XSS")
	}
	if refreshTokenCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("refresh_token diharapkan SameSite=Strict, didapat %v", refreshTokenCookie.SameSite)
	}
	if refreshTokenCookie.Path != "/api/auth" {
		t.Errorf("refresh_token diharapkan memiliki path restricted /api/auth, didapat %s", refreshTokenCookie.Path)
	}

	if csrfTokenCookie == nil {
		t.Fatal("Cookie csrf_token tidak ditemukan")
	}
	if csrfTokenCookie.HttpOnly {
		t.Errorf("csrf_token HARUS HttpOnly=false agar dapat dibaca oleh script Frontend (Double Submit)")
	}

	// 3. Akses Protected Endpoint (GET /api/user/profile) dengan Access Token Cookie
	profileReq := httptest.NewRequest("GET", "/api/user/profile", nil)
	profileReq.AddCookie(accessTokenCookie)
	profileRec := httptest.NewRecorder()
	app.ServeHTTP(profileRec, profileReq)

	if profileRec.Code != http.StatusOK {
		t.Fatalf("Gagal mengakses protected profile, status: %d, body: %s", profileRec.Code, profileRec.Body.String())
	}

	// 4. Test Proteksi CSRF pada Mutasi Data (PUT /api/user/profile)
	// Skenario 4a: Tanpa header X-CSRF-Token -> HARUS DITOLAK (Status 403 Forbidden)
	putReqWithoutCSRF := httptest.NewRequest("PUT", "/api/user/profile", bytes.NewBufferString(`{"display_name":"Budi Update"}`))
	putReqWithoutCSRF.Header.Set("Content-Type", "application/json")
	putReqWithoutCSRF.AddCookie(accessTokenCookie)
	putReqWithoutCSRF.AddCookie(csrfTokenCookie)
	putRecWithoutCSRF := httptest.NewRecorder()
	app.ServeHTTP(putRecWithoutCSRF, putReqWithoutCSRF)

	if putRecWithoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("Diharapkan 403 Forbidden ketika X-CSRF-Token absen, tapi didapat: %d", putRecWithoutCSRF.Code)
	}

	// Skenario 4b: Dengan X-CSRF-Token yang salah/palsu -> HARUS DITOLAK (Status 403 Forbidden)
	putReqFakeCSRF := httptest.NewRequest("PUT", "/api/user/profile", bytes.NewBufferString(`{"display_name":"Budi Update"}`))
	putReqFakeCSRF.Header.Set("Content-Type", "application/json")
	putReqFakeCSRF.Header.Set("X-CSRF-Token", "fake-tampered-token")
	putReqFakeCSRF.AddCookie(accessTokenCookie)
	putReqFakeCSRF.AddCookie(csrfTokenCookie)
	putRecFakeCSRF := httptest.NewRecorder()
	app.ServeHTTP(putRecFakeCSRF, putReqFakeCSRF)

	if putRecFakeCSRF.Code != http.StatusForbidden {
		t.Fatalf("Diharapkan 403 Forbidden ketika X-CSRF-Token palsu, tapi didapat: %d", putRecFakeCSRF.Code)
	}

	// Skenario 4c: Dengan X-CSRF-Token yang valid sesuai cookie -> HARUS SUKSES (Status 200 OK)
	putReqValid := httptest.NewRequest("PUT", "/api/user/profile", bytes.NewBufferString(`{"display_name":"Budi Santoso Baru"}`))
	putReqValid.Header.Set("Content-Type", "application/json")
	putReqValid.Header.Set("X-CSRF-Token", csrfTokenCookie.Value)
	putReqValid.AddCookie(accessTokenCookie)
	putReqValid.AddCookie(csrfTokenCookie)
	putRecValid := httptest.NewRecorder()
	app.ServeHTTP(putRecValid, putReqValid)

	if putRecValid.Code != http.StatusOK {
		t.Fatalf("Diharapkan 200 OK ketika X-CSRF-Token valid, tapi didapat: %d, body: %s", putRecValid.Code, putRecValid.Body.String())
	}

	// 5. Test Refresh Token Rotation (RTR) (POST /api/auth/refresh)
	refreshReq := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	refreshReq.Header.Set("X-CSRF-Token", csrfTokenCookie.Value)
	refreshReq.AddCookie(refreshTokenCookie)
	refreshReq.AddCookie(csrfTokenCookie)
	refreshRec := httptest.NewRecorder()
	app.ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusOK {
		t.Fatalf("Gagal melakukan refresh token, status: %d, body: %s", refreshRec.Code, refreshRec.Body.String())
	}

	// Dapatkan cookie baru hasil rotasi
	newCookies := refreshRec.Result().Cookies()
	var newRefreshTokenCookie, newAccessTokenCookie *http.Cookie
	for _, c := range newCookies {
		if c.Name == cookie.RefreshTokenCookieName {
			newRefreshTokenCookie = c
		}
		if c.Name == cookie.AccessTokenCookieName {
			newAccessTokenCookie = c
		}
	}
	if newRefreshTokenCookie == nil || newAccessTokenCookie == nil {
		t.Fatal("Pasangan token baru hasil rotasi tidak ditemukan di cookie")
	}

	if newRefreshTokenCookie.Value == refreshTokenCookie.Value {
		t.Errorf("Refresh token lama tidak dirotasi! Nilai token sama persis")
	}

	// 6. DETEKSI REUSE ATTACK: Coba gunakan Refresh Token LAMA yang sudah di-rotasi
	reuseReq := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	reuseReq.Header.Set("X-CSRF-Token", csrfTokenCookie.Value)
	reuseReq.AddCookie(refreshTokenCookie) // Gunakan token lama!
	reuseReq.AddCookie(csrfTokenCookie)
	reuseRec := httptest.NewRecorder()
	app.ServeHTTP(reuseRec, reuseReq)

	if reuseRec.Code != http.StatusForbidden {
		t.Fatalf("Diharapkan 403 Forbidden saat reuse attack terjadi, tetapi didapat: %d, body: %s", reuseRec.Code, reuseRec.Body.String())
	}

	// 7. Logout dan Pembersihan Cookie
	logoutReq := httptest.NewRequest("POST", "/api/auth/logout", nil)
	logoutReq.Header.Set("X-CSRF-Token", csrfTokenCookie.Value)
	logoutReq.AddCookie(newAccessTokenCookie)
	logoutReq.AddCookie(newRefreshTokenCookie)
	logoutReq.AddCookie(csrfTokenCookie)
	logoutRec := httptest.NewRecorder()
	app.ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusOK {
		t.Fatalf("Logout gagal, status: %d, body: %s", logoutRec.Code, logoutRec.Body.String())
	}

	// Periksa apakah cookies dibersihkan (MaxAge: -1)
	for _, c := range logoutRec.Result().Cookies() {
		if c.MaxAge != -1 {
			t.Errorf("Cookie %s harus memiliki MaxAge=-1 saat logout, didapat: %d", c.Name, c.MaxAge)
		}
	}
}
