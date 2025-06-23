package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/device/postgres/sqlc"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

type DeviceStorage struct {
	pool    *pgxpool.Pool
	txMgr   TransactionManager
	queries *sqlc.Queries
}

func NewDeviceStorage(pool *pgxpool.Pool, txMgr TransactionManager) *DeviceStorage {
	return &DeviceStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: sqlc.New(pool),
	}
}

type TransactionManager interface {
	ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

func (s *DeviceStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	const method = "storage.device.postgres.RegisterDevice"

	params := sqlc.RegisterDeviceParams{
		ID:            device.ID,
		UserID:        device.UserID,
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

func (s *DeviceStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "storage.device.postgres.GetUserDeviceID"

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

func (s *DeviceStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	const method = "storage.device.postgres.UpdateLastVisitedAt"

	params := sqlc.UpdateLastVisitedAtParams{
		ID:            session.DeviceID,
		LastVisitedAt: session.LastVisitedAt,
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

func (s *DeviceStorage) DeleteAllUserDevices(ctx context.Context, userID string) error {
	const method = "storage.device.postgres.DeleteAllUserDevices"

	// Delete all user devices within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).DeleteAllUserDevices(ctx, userID)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Delete all user devices without transaction
		err = s.queries.DeleteAllUserDevices(ctx, userID)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to delete all user devices: %w", method, err)
	}

	return nil
}
