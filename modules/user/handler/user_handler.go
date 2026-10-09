package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yudhiana/web-api/modules/user/domain"
	"github.com/yudhiana/web-api/modules/user/service"
	"github.com/yudhiana/web-api/pkg/security"
)

type UserHandler struct {
	userService service.UserService
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// GetProfile mengembalikan data profil pengguna yang sedang login
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID, ok := security.GetUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"Unauthorized: Sesi autentikasi tidak ditemukan"}`, http.StatusUnauthorized)
		return
	}

	profile, err := h.userService.GetProfile(r.Context(), userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			http.Error(w, `{"error":"Pengguna tidak ditemukan"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Gagal memuat profil: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profil berhasil dimuat",
		"data":    profile,
	})
}

// UpdateProfile memperbarui profil pengguna saat ini (dilindungi Auth & CSRF)
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID, ok := security.GetUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var dto domain.UpdateUserDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, `{"error":"Payload JSON tidak valid"}`, http.StatusBadRequest)
		return
	}

	updated, err := h.userService.UpdateProfile(r.Context(), userID, dto)
	if err != nil {
		http.Error(w, `{"error":"Gagal memperbarui profil: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profil berhasil diperbarui",
		"data":    updated,
	})
}
