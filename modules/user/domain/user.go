package domain

import (
	"errors"
	"time"
)

var (
	ErrUserNotFound      = errors.New("pengguna tidak ditemukan")
	ErrUserAlreadyExists = errors.New("email sudah terdaftar")
	ErrInvalidPassword   = errors.New("kata sandi tidak cocok")
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	DisplayName  string    `json:"display_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateUserDTO struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	DisplayName string `json:"display_name"`
}

type UpdateUserDTO struct {
	DisplayName string `json:"display_name"`
}

type UserResponse struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
}
