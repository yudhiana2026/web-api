package repository

import (
	"context"
	"sync"

	"github.com/yudhiana/web-api/modules/auth/domain"
)

type SessionRepository interface {
	Save(ctx context.Context, session *domain.RefreshTokenSession) error
	FindByID(ctx context.Context, id string) (*domain.RefreshTokenSession, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForUser(ctx context.Context, userID string) error
}

type memorySessionRepository struct {
	mu       sync.RWMutex
	sessions map[string]*domain.RefreshTokenSession // key: session.ID (token JTI)
}

func NewMemorySessionRepository() SessionRepository {
	return &memorySessionRepository{
		sessions: make(map[string]*domain.RefreshTokenSession),
	}
}

func (r *memorySessionRepository) Save(ctx context.Context, session *domain.RefreshTokenSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessions[session.ID] = session
	return nil
}

func (r *memorySessionRepository) FindByID(ctx context.Context, id string) (*domain.RefreshTokenSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, exists := r.sessions[id]
	if !exists {
		return nil, domain.ErrTokenInvalid
	}
	return session, nil
}

func (r *memorySessionRepository) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[id]
	if !exists {
		return domain.ErrTokenInvalid
	}

	session.Revoked = true
	return nil
}

func (r *memorySessionRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, session := range r.sessions {
		if session.UserID == userID {
			session.Revoked = true
		}
	}
	return nil
}
