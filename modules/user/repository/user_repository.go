package repository

import (
	"context"
	"sync"

	"github.com/yudhiana/web-api/modules/user/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByID(ctx context.Context, id string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
}

type memoryUserRepository struct {
	mu      sync.RWMutex
	users   map[string]*domain.User
	byEmail map[string]string
}

func NewMemoryUserRepository() UserRepository {
	return &memoryUserRepository{
		users:   make(map[string]*domain.User),
		byEmail: make(map[string]string),
	}
}

func (r *memoryUserRepository) Create(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byEmail[user.Email]; exists {
		return domain.ErrUserAlreadyExists
	}

	r.users[user.ID] = user
	r.byEmail[user.Email] = user.ID
	return nil
}

func (r *memoryUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, exists := r.byEmail[email]
	if !exists {
		return nil, domain.ErrUserNotFound
	}

	user, ok := r.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

func (r *memoryUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

func (r *memoryUserRepository) Update(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[user.ID]; !exists {
		return domain.ErrUserNotFound
	}

	r.users[user.ID] = user
	return nil
}
