package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"github.com/rshelekhov/sso/src/infrastructure/storage/session/postgres/sqlc"
)

type Storage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewSessionStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *Storage) CreateSession(ctx context.Context, session entity.Session) error {
	const method = "user.storage.CreateSession"

	if err := s.Queries.CreateUserSession(ctx, sqlc.CreateUserSessionParams{
		UserID:        session.UserID,
		AppID:         session.AppID,
		DeviceID:      session.DeviceID,
		RefreshToken:  session.RefreshToken,
		LastVisitedAt: session.LastVisitedAt,
		ExpiresAt:     session.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to create user session: %w", method, err)
	}

	return nil
}

func (s *Storage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	const method = "user.storage.GetSessionByRefreshToken"

	// TODO: add constraint that user can have only active sessions for 5 devices
	session, err := s.Queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.Session{}, storage.ErrSessionNotFound
		}
		return entity.Session{}, fmt.Errorf("%s: failed to get session: %w", method, err)
	}

	return entity.Session{
		UserID:        session.UserID,
		AppID:         session.AppID,
		DeviceID:      session.DeviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: session.LastVisitedAt,
		ExpiresAt:     session.ExpiresAt,
	}, nil
}

func (s *Storage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	const method = "user.storage.UpdateLastVisitedAt"

	if err := s.Queries.UpdateLastVisitedAt(ctx, sqlc.UpdateLastVisitedAtParams{
		ID:            session.DeviceID,
		LastVisitedAt: session.LastVisitedAt,
		AppID:         session.AppID,
	}); err != nil {
		return fmt.Errorf("%s: failed to update last visited at: %w", method, err)
	}
	return nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "user.storage.DeleteRefreshToken"

	if err := s.Queries.DeleteRefreshTokenFromSession(ctx, refreshToken); err != nil {
		return fmt.Errorf("%s: failed to delete refresh jwtoken: %w", method, err)
	}

	return nil
}

func (s *Storage) DeleteSession(ctx context.Context, session entity.Session) error {
	const method = "user.storage.DeleteSession"

	if err := s.Queries.DeleteSession(ctx, sqlc.DeleteSessionParams{
		UserID:   session.UserID,
		AppID:    session.AppID,
		DeviceID: session.DeviceID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrSessionNotFound
		}
		return fmt.Errorf("%s: failed to delete session: %w", method, err)
	}

	return nil
}

func (s *Storage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	const method = "user.storage.DeleteAllSessions"

	if err := s.Queries.DeleteAllSessions(ctx, sqlc.DeleteAllSessionsParams{
		UserID: userID,
		AppID:  appID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrSessionsNotFound
		}
		return fmt.Errorf("%s: failed to delete all sessions: %w", method, err)
	}

	return nil
}

func (s *Storage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "user.storage.GetUserDeviceID"

	deviceID, err := s.Queries.GetUserDeviceID(ctx, sqlc.GetUserDeviceIDParams{
		UserID:    userID,
		UserAgent: userAgent,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserDeviceNotFound
		}
		return "", fmt.Errorf("%s: failed to get id of user device: %w", method, err)
	}

	return deviceID, nil
}

func (s *Storage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	const method = "user.storage.RegisterDevice"

	if err := s.Queries.RegisterDevice(ctx, sqlc.RegisterDeviceParams{
		ID:            device.ID,
		UserID:        device.UserID,
		AppID:         device.AppID,
		UserAgent:     device.UserAgent,
		Ip:            device.IP,
		Detached:      device.Detached,
		LastVisitedAt: device.LastVisitedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to register user device: %w", method, err)
	}

	return nil
}
