package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/storage/postgres/sqlc"
	"strconv"
	"time"
)

type AuthStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAuthStorage(pool *pgxpool.Pool) port.AuthStorage {
	return &AuthStorage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *AuthStorage) Transaction(ctx context.Context, fn func(storage port.AuthStorage) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				err = fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
			}
		} else {
			err = tx.Commit(ctx)
		}
	}()

	err = fn(s)

	return err
}

func (s *AuthStorage) checkAppIDExists(ctx context.Context, appID string) (bool, error) {
	const method = "user.storage.CheckAppIDExists"

	exists, err := s.Queries.CheckAppIDExists(ctx, appID)
	if err != nil {
		return false, fmt.Errorf("%s: failed to check if app ID exists: %w", method, err)
	}
	return exists, nil
}

func (s *AuthStorage) ValidateAppID(ctx context.Context, appID string) error {
	appIDExists, err := s.checkAppIDExists(ctx, appID)
	if err != nil {
		return err
	}
	if !appIDExists {
		return le.ErrAppIDDoesNotExist
	}
	return nil
}

// GetUserStatusByEmail returns the status of the user with the given email
func (s *AuthStorage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "user.storage.GetUserStatusByEmail"

	status, err := s.Queries.GetUserStatusByEmail(ctx, email)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// GetUserStatusByID returns the status of the user with the given userID
func (s *AuthStorage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "user.storage.GetUserStatusByID"

	status, err := s.Queries.GetUserStatusByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// ReplaceSoftDeletedUser replaces a soft deleted user with the given user
func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user model.User) error {
	const method = "user.storage.ReplaceSoftDeletedUser"

	if err := s.Queries.RegisterUser(ctx, sqlc.RegisterUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		Verified: pgtype.Bool{
			Bool:  user.Verified,
			Valid: true,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}
	return nil
}

// RegisterUser creates a new user
func (s *AuthStorage) RegisterUser(ctx context.Context, user model.User) error {
	const method = "user.storage.insertNewUser"

	if err := s.Queries.RegisterUser(ctx, sqlc.RegisterUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		Verified: pgtype.Bool{
			Bool:  user.Verified,
			Valid: true,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to insert new user: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) CreateToken(ctx context.Context, data model.TokenData) error {
	const method = "user.storage.CreateToken"

	if err := s.Queries.CreateToken(ctx, sqlc.CreateTokenParams{
		Token:       data.Token,
		UserID:      data.UserID,
		AppID:       data.AppID,
		Endpoint:    data.Endpoint,
		Recipient:   data.Email,
		TokenTypeID: int32(data.Type),
		CreatedAt:   data.CreatedAt,
		ExpiresAt:   data.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to create token: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) GetTokenData(ctx context.Context, verificationToken string) (model.TokenData, error) {
	const method = "user.storage.GetTokenData"

	data, err := s.Queries.GetTokenData(ctx, verificationToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.TokenData{}, le.ErrTokenNotFound
		}
		return model.TokenData{}, fmt.Errorf("%s: failed to get token data: %w", method, err)
	}

	return model.TokenData{
		Token:     data.Token,
		UserID:    data.UserID,
		AppID:     data.AppID,
		Endpoint:  data.Endpoint,
		Email:     data.Recipient,
		Type:      model.TokenType(data.TokenTypeID),
		ExpiresAt: data.ExpiresAt,
	}, nil
}

func (s *AuthStorage) GetUserIDByToken(ctx context.Context, token string) (string, error) {
	const method = "user.storage.GetUserIDByToken"

	userID, err := s.Queries.GetUserIDByToken(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", le.ErrTokenNotFound
		}
		return "", fmt.Errorf("%s: failed to get user id by token: %w", method, err)
	}

	return userID, nil
}

func (s *AuthStorage) DeleteToken(ctx context.Context, verificationToken string) error {
	const method = "user.storage.DeleteToken"

	if err := s.Queries.DeleteToken(ctx, verificationToken); err != nil {
		return fmt.Errorf("%s: failed to delete email verification token: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, appID string) error {
	const method = "user.storage.MarkEmailVerified"

	if err := s.Queries.MarkEmailVerified(ctx, sqlc.MarkEmailVerifiedParams{
		ID:    userID,
		AppID: appID,
	}); err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) GetUserByEmail(ctx context.Context, email, appID string) (model.User, error) {
	const method = "user.storage.GetUserByEmail"

	user, err := s.Queries.GetUserByEmail(ctx, sqlc.GetUserByEmailParams{
		Email: email,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return model.User{
		ID:        user.ID,
		Email:     user.Email,
		AppID:     user.AppID,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserByID(ctx context.Context, userID, appID string) (model.User, error) {
	const method = "user.storage.GetUserByID"

	user, err := s.Queries.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	return model.User{
		Email:     user.Email,
		AppID:     user.AppID,
		Verified:  user.Verified.Bool,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserData(ctx context.Context, userID, appID string) (model.User, error) {
	const method = "user.storage.GetUserData"

	user, err := s.Queries.GetUserData(ctx, sqlc.GetUserDataParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return model.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "user.storage.GetUserDeviceID"

	deviceID, err := s.Queries.GetUserDeviceID(ctx, sqlc.GetUserDeviceIDParams{
		UserID:    userID,
		UserAgent: userAgent,
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", le.ErrUserDeviceNotFound
		}
		return "", fmt.Errorf("%s: failed to get id of user device: %w", method, err)
	}

	return deviceID, nil
}

func (s *AuthStorage) UpdateLatestVisitedAt(ctx context.Context, deviceID, appID string, latestVisitedAt time.Time) error {
	const method = "user.storage.UpdateLatestVisitedAt"

	if err := s.Queries.UpdateLatestLoginAt(ctx, sqlc.UpdateLatestLoginAtParams{
		ID:            deviceID,
		LastVisitedAt: latestVisitedAt,
		AppID:         appID,
	}); err != nil {
		return fmt.Errorf("%s: failed to update latest login at: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) RegisterDevice(ctx context.Context, device model.UserDevice) error {
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

func (s *AuthStorage) CreateUserSession(ctx context.Context, session model.Session) error {
	const method = "user.storage.CreateUserSession"

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

func (s *AuthStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (model.Session, error) {
	const method = "user.storage.GetSessionByRefreshToken"

	// TODO: add constraint that user can have only active sessions for 5 devices
	session, err := s.Queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Session{}, le.ErrSessionNotFound
		}
		return model.Session{}, fmt.Errorf("%s: failed to get session: %w", method, err)
	}

	return model.Session{
		UserID:        session.UserID,
		AppID:         session.AppID,
		DeviceID:      session.DeviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: session.LastVisitedAt,
		ExpiresAt:     session.ExpiresAt,
	}, nil
}

func (s *AuthStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "user.storage.DeleteRefreshToken"

	if err := s.Queries.DeleteRefreshTokenFromSession(ctx, refreshToken); err != nil {
		return fmt.Errorf("%s: failed to delete refresh jwtoken: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) DeleteSession(ctx context.Context, userID, deviceID, appID string) error {
	const method = "user.storage.DeleteSession"

	if err := s.Queries.DeleteSession(ctx, sqlc.DeleteSessionParams{
		UserID:   userID,
		AppID:    appID,
		DeviceID: deviceID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return le.ErrSessionNotFound
		}
		return fmt.Errorf("%s: failed to delete session: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	const method = "user.storage.DeleteAllSessions"

	if err := s.Queries.DeleteAllSessions(ctx, sqlc.DeleteAllSessionsParams{
		UserID: userID,
		AppID:  appID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return le.ErrSessionsNotFound
		}
		return fmt.Errorf("%s: failed to delete all sessions: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) CheckEmailUniqueness(ctx context.Context, user model.User) error {
	const method = "user.storage.CheckEmailUniqueness"

	existingUser, err := s.Queries.GetUserByEmail(ctx, sqlc.GetUserByEmailParams{
		Email: user.Email,
		AppID: user.AppID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // Email is unique as user with this email doesn't exist
		}
		return fmt.Errorf("%s: failed to check email uniqueness: %w", method, err)
	}

	if existingUser.ID != user.ID {
		return le.ErrEmailAlreadyTaken
	}

	return nil
}

func (s *AuthStorage) UpdateUser(ctx context.Context, user model.User) error {
	const method = "user.storage.UpdateUser"

	// Prepare the dynamic update query based on the provided fields
	queryUpdate := "UPDATE users SET updated_at = $1"
	queryParams := []interface{}{user.UpdatedAt}

	if user.Email != "" {
		queryUpdate += ", email = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.Email)
	}

	if user.PasswordHash != "" {
		queryUpdate += ", password_hash = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.PasswordHash)
	}

	// Add condition for the specific user ID
	queryUpdate += " WHERE id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.ID)

	// Add condition for the specific app ID
	queryUpdate += " AND app_id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.AppID)

	// Execute the update query
	_, err := s.Exec(ctx, queryUpdate, queryParams...)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return le.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to execute update query: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) DeleteUser(ctx context.Context, user model.User) error {
	const method = "user.storage.DeleteUser"

	if err := s.Queries.DeleteUser(ctx, sqlc.DeleteUserParams{
		ID:    user.ID,
		AppID: user.AppID,
		DeletedAt: pgtype.Timestamptz{
			Time:  user.DeletedAt,
			Valid: true,
		},
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return le.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to delete user: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) DeleteAllTokens(ctx context.Context, userID, appID string) error {
	const method = "user.storage.DeleteAllTokens"

	if err := s.Queries.DeleteAllTokens(ctx, sqlc.DeleteAllTokensParams{
		UserID: userID,
		AppID:  appID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return le.ErrTokensNotFound
		}
		return fmt.Errorf("%s: failed to delete tokens: %w", method, err)
	}

	return nil
}
