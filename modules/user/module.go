package user

import (
	"net/http"

	"github.com/yudhiana/web-api/modules/user/handler"
	"github.com/yudhiana/web-api/modules/user/repository"
	"github.com/yudhiana/web-api/modules/user/service"
)

// Module membungkus seluruh dependensi modul User
type Module struct {
	Repo    repository.UserRepository
	Service service.UserService
	Handler *handler.UserHandler
}

// NewModule menginisialisasi modul User
func NewModule() *Module {
	repo := repository.NewMemoryUserRepository()
	svc := service.NewUserService(repo)
	h := handler.NewUserHandler(svc)

	return &Module{
		Repo:    repo,
		Service: svc,
		Handler: h,
	}
}

// RegisterRoutes mendaftarkan rute internal modul User ke HTTP Multiplexer
func (m *Module) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	mux.Handle("GET /api/user/profile", requireAuth(http.HandlerFunc(m.Handler.GetProfile)))
	mux.Handle("PUT /api/user/profile", requireAuth(http.HandlerFunc(m.Handler.UpdateProfile)))
}
