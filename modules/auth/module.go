package auth

import (
	"net/http"

	"github.com/yudhiana/web-api/config"
	"github.com/yudhiana/web-api/modules/auth/handler"
	"github.com/yudhiana/web-api/modules/auth/middleware"
	"github.com/yudhiana/web-api/modules/auth/repository"
	"github.com/yudhiana/web-api/modules/auth/service"
	userService "github.com/yudhiana/web-api/modules/user/service"
	"github.com/yudhiana/web-api/pkg/cookie"
	"github.com/yudhiana/web-api/pkg/security"
)

// Module membungkus seluruh komponen dan dependensi modul Auth
type Module struct {
	SessionRepo    repository.SessionRepository
	AuthService    service.AuthService
	AuthHandler    *handler.AuthHandler
	AuthMiddleware *middleware.AuthMiddleware
	CSRFMiddleware *middleware.CSRFMiddleware
}

// NewModule menginisialisasi modul Auth dengan dependensi yang dibutuhkan
func NewModule(
	cfg *config.Config,
	userSvc userService.UserService,
	cookieMgr *cookie.Manager,
	jwtMgr *security.JWTManager,
	csrfMgr *security.CSRFManager,
) *Module {
	sessionRepo := repository.NewMemorySessionRepository()
	authSvc := service.NewAuthService(userSvc, sessionRepo, jwtMgr, csrfMgr)
	authHdl := handler.NewAuthHandler(authSvc, csrfMgr, cookieMgr)
	authMid := middleware.NewAuthMiddleware(jwtMgr)
	csrfMid := middleware.NewCSRFMiddleware(csrfMgr, cookieMgr)

	return &Module{
		SessionRepo:    sessionRepo,
		AuthService:    authSvc,
		AuthHandler:    authHdl,
		AuthMiddleware: authMid,
		CSRFMiddleware: csrfMid,
	}
}

// RegisterRoutes mendaftarkan rute internal modul Auth ke HTTP router
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// Endpoint Publik
	mux.HandleFunc("POST /api/auth/register", m.AuthHandler.Register)
	mux.HandleFunc("POST /api/auth/login", m.AuthHandler.Login)
	mux.HandleFunc("GET /api/csrf-token", m.AuthHandler.GetCSRFToken)

	// Endpoint Refresh Token (Rotasi token)
	mux.HandleFunc("POST /api/auth/refresh", m.AuthHandler.RefreshToken)

	// Endpoint Logout (Memerlukan token autentikasi)
	mux.Handle("POST /api/auth/logout", m.AuthMiddleware.RequireAuth(http.HandlerFunc(m.AuthHandler.Logout)))
}
