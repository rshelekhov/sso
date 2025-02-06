package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/session/postgres/sqlc"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

type SessionStorage struct {
	pool    *pgxpool.Pool
	txMgr   transaction.PostgresManager
	queries *sqlc.Queries
}

func NewSessionStorage(pool *pgxpool.Pool, txMgr transaction.PostgresManager) *SessionStorage {
	return &SessionStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: sqlc.New(pool),
	}
}

func (s *SessionStorage) CreateSession(ctx context.Context, session entity.Session) error {
	const method = "storage.session.postgres.CreateSession"

	params := sqlc.CreateUserSessionParams{
		UserID:        session.UserID,
		AppID:         session.AppID,
		DeviceID:      session.DeviceID,
		RefreshToken:  session.RefreshToken,
		LastVisitedAt: session.LastVisitedAt,
		ExpiresAt:     session.ExpiresAt,
	}

	// Save session within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).CreateUserSession(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Save session without transaction
		err = s.queries.CreateUserSession(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to create user session: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	const method = "storage.session.postgres.GetSessionByRefreshToken"

	// TODO: add constraint that user can have only active sessions for 5 devices
	session, err := s.queries.GetSessionByRefreshToken(ctx, refreshToken)
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

func (s *SessionStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	const method = "storage.session.postgres.UpdateLastVisitedAt"

	params := sqlc.UpdateLastVisitedAtParams{
		ID:            session.DeviceID,
		LastVisitedAt: session.LastVisitedAt,
		AppID:         session.AppID,
	}

	// Update last visited at within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).UpdateLastVisitedAt(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Update last visited at without transaction
		err = s.queries.UpdateLastVisitedAt(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to update last visited at: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "storage.session.postgres.DeleteRefreshToken"

	if err := s.queries.DeleteRefreshTokenFromSession(ctx, refreshToken); err != nil {
		return fmt.Errorf("%s: failed to delete refresh jwtoken: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	const method = "storage.session.postgres.DeleteSession"

	if err := s.queries.DeleteSession(ctx, sqlc.DeleteSessionParams{
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

func (s *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	const method = "storage.session.postgres.DeleteAllSessions"

	params := sqlc.DeleteAllSessionsParams{
		UserID: userID,
		AppID:  appID,
	}

	// Delete all sessions within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).DeleteAllSessions(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Delete all sessions without transaction
		err = s.queries.DeleteAllSessions(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to delete all sessions: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "storage.session.postgres.GetUserDeviceID"

	deviceID, err := s.queries.GetUserDeviceID(ctx, sqlc.GetUserDeviceIDParams{
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

func (s *SessionStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	const method = "storage.session.postgres.RegisterDevice"

	params := sqlc.RegisterDeviceParams{
		ID:            device.ID,
		UserID:        device.UserID,
		AppID:         device.AppID,
		UserAgent:     device.UserAgent,
		Ip:            device.IP,
		Detached:      device.Detached,
		LastVisitedAt: device.LastVisitedAt,
	}

	// Register device within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).RegisterDevice(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Register device without transaction
		err = s.queries.RegisterDevice(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to register user device: %w", method, err)
	}

	return nil
}
