package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/yudhiana/web-api/modules/user/domain"
	"github.com/yudhiana/web-api/modules/user/repository"
)

type UserService interface {
	CreateUser(ctx context.Context, dto domain.CreateUserDTO) (*domain.UserResponse, error)
	VerifyCredentials(ctx context.Context, email, password string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetProfile(ctx context.Context, id string) (*domain.UserResponse, error)
	UpdateProfile(ctx context.Context, id string, dto domain.UpdateUserDTO) (*domain.UserResponse, error)
}

type userService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) CreateUser(ctx context.Context, dto domain.CreateUserDTO) (*domain.UserResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi kata sandi: %w", err)
	}

	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("gagal membuat user ID: %w", err)
	}
	userID := hex.EncodeToString(idBytes)

	role := dto.Role
	if role == "" {
		role = "user"
	}

	displayName := dto.DisplayName
	if displayName == "" {
		displayName = dto.Email
	}

	now := time.Now()
	user := &domain.User{
		ID:           userID,
		Email:        dto.Email,
		PasswordHash: string(hashedPassword),
		Role:         role,
		DisplayName:  displayName,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return toUserResponse(user), nil
}

func (s *userService) VerifyCredentials(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidPassword
	}

	return user, nil
}

func (s *userService) GetByID(ctx context.Context, id string) (*domain.User, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *userService) GetProfile(ctx context.Context, id string) (*domain.UserResponse, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return toUserResponse(user), nil
}

func (s *userService) UpdateProfile(ctx context.Context, id string, dto domain.UpdateUserDTO) (*domain.UserResponse, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if dto.DisplayName != "" {
		user.DisplayName = dto.DisplayName
	}
	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return toUserResponse(user), nil
}

func toUserResponse(u *domain.User) *domain.UserResponse {
	return &domain.UserResponse{
		ID:          u.ID,
		Email:       u.Email,
		Role:        u.Role,
		DisplayName: u.DisplayName,
		CreatedAt:   u.CreatedAt,
	}
}
