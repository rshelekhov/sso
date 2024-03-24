package usecase

import (
	"context"
	"errors"
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/lib/auth"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"log/slog"
	"time"
)

type AuthUsecase struct {
	log     *slog.Logger
	storage port.AuthStorage
	jwt     *jwtauth.TokenService
}

// NewAuthUsecase returns a new instance of the AuthUsecase usecase
func NewAuthUsecase(
	log *slog.Logger,
	storage port.AuthStorage,
	jwt *jwtauth.TokenService,
) *AuthUsecase {
	return &AuthUsecase{
		log:     log,
		storage: storage,
		jwt:     jwt,
	}
}

// Login checks if user with given credentials exists in the system
//
// Is user exists, but password is incorrect, it will return an error
// If user doesn't exist, it will return an error
func (u *AuthUsecase) Login(ctx context.Context, data *model.UserRequestData) (jwtauth.TokenData, error) {
	const method = "usecase.AuthUsecase.Login"

	log := u.log.With(
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	user, err := u.storage.GetUserByEmail(ctx, data.Email)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserByEmail, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, u.jwt, user, data.Password); err != nil {
		if errors.Is(err, le.ErrPasswordsDontMatch) {
			log.Error("%w: %w", le.ErrPasswordsDontMatch, err)
			return jwtauth.TokenData{}, le.ErrPasswordsDontMatch
		}
		log.Error("%w: %w", le.ErrFailedToCheckIfPasswordMatch, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData, err := u.CreateUserSession(ctx, log, user.ID, userDevice)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateUserSession, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	log.Info("user authenticated, tokens created", slog.String(key.UserID, user.ID))

	return tokenData, nil
}

// verifyPassword checks if password is correct
func (u *AuthUsecase) verifyPassword(ctx context.Context, jwt *jwtauth.TokenService, user model.User, password string) error {
	const method = "user.AuthUsecase.verifyPassword"

	user, err := u.storage.GetUserData(ctx, user.ID)
	if err != nil {
		return err
	}

	matched, err := auth.PasswordMatch(user.PasswordHash, password, []byte(jwt.PasswordHashSalt))
	if err != nil {
		return err
	}

	if !matched {
		return le.ErrPasswordsDontMatch
	}

	return nil
}

// RegisterNewUser creates new user in the system and returns token
//
// If user with given email already exists, it will return an error
func (u *AuthUsecase) RegisterNewUser(ctx context.Context, data *model.UserRequestData) (jwtauth.TokenData, error) {
	const method = "usecase.AuthUsecase.CreateUser"

	log := u.log.With(
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	hash, err := auth.PasswordHashBcrypt(
		data.Password,
		u.jwt.PasswordHashCost,
		[]byte(u.jwt.PasswordHashSalt),
	)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGeneratePasswordHash, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	user := model.User{
		ID:           ksuid.New().String(),
		Email:        data.Email,
		PasswordHash: hash,
		UpdatedAt:    time.Now(),
	}

	if err = u.storage.CreateUser(ctx, user); err != nil {
		// TODO: return a custom error

		log.Error("%w: %w", le.ErrFailedToCreateUser, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData, err := u.CreateUserSession(ctx, log, user.ID, userDevice)
	if err != nil {
		return jwtauth.TokenData{}, err
	}

	log.Info("user and tokens created", slog.String(key.UserID, user.ID))

	return tokenData, nil
}

// TODO: Move sessions from Postgres to Redis
// CreateUserSession creates new user session in the system and returns token
func (u *AuthUsecase) CreateUserSession(
	ctx context.Context,
	log *slog.Logger,
	userID string,
	userDeviceRequest model.UserDeviceRequestData,
) (
	jwtauth.TokenData,
	error,
) {
	const method = "usecase.AuthUsecase.CreateUserSession"

	log = log.With(
		slog.String(key.Method, method),
		slog.String(key.UserID, userID),
	)

	additionalClaims := map[string]interface{}{
		jwtauth.ContextUserID: userID,
	}

	deviceID, err := u.getDeviceID(ctx, userID, userDeviceRequest)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetDeviceID, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	accessToken, err := u.jwt.NewAccessToken(additionalClaims)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateAccessToken, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	refreshToken, err := u.jwt.NewRefreshToken()
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateRefreshToken, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	lastVisitedAt := time.Now()
	expiresAt := time.Now().Add(u.jwt.RefreshTokenTTL)

	session := model.Session{
		UserID:        userID,
		DeviceID:      deviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: lastVisitedAt,
		ExpiresAt:     expiresAt,
	}

	if err = u.storage.CreateUserSession(ctx, session); err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateUserSession, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	if err = u.updateLastVisitedAt(ctx, deviceID, lastVisitedAt); err != nil {
		log.Error("%w: %w", le.ErrFailedToUpdateLastVisitedAt, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	additionalFields := map[string]string{key.UserID: userID}
	tokenData := jwtauth.TokenData{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		Domain:           u.jwt.RefreshTokenCookieDomain,
		Path:             u.jwt.RefreshTokenCookiePath,
		ExpiresAt:        expiresAt,
		HTTPOnly:         true,
		AdditionalFields: additionalFields,
	}

	return tokenData, nil
}

func (u *AuthUsecase) getDeviceID(ctx context.Context, userID string, userDeviceRequest model.UserDeviceRequestData) (string, error) {
	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, userDeviceRequest.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			return u.registerDevice(ctx, userID, userDeviceRequest)
		}
		return "", err
	}

	return deviceID, nil
}

func (u *AuthUsecase) registerDevice(ctx context.Context, userID string, userDeviceRequest model.UserDeviceRequestData) (string, error) {
	userDevice := model.UserDevice{
		ID:            ksuid.New().String(),
		UserID:        userID,
		UserAgent:     userDeviceRequest.UserAgent,
		IP:            userDeviceRequest.IP,
		Detached:      false,
		LastVisitedAt: time.Now(),
	}

	if err := u.storage.RegisterDevice(ctx, userDevice); err != nil {
		// TODO: add logging and return a custom error
		return "", err
	}

	return userDevice.ID, nil
}

func (u *AuthUsecase) updateLastVisitedAt(ctx context.Context, deviceID string, lastVisitedAt time.Time) error {
	return u.storage.UpdateLastVisitedAt(ctx, deviceID, lastVisitedAt)
}

func (u *AuthUsecase) RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (jwtauth.TokenData, error) {
	const method = "usecase.AuthUsecase.RefreshTokens"

	log := u.log.With(
		slog.String(key.Method, method),
	)

	session, err := u.checkSessionAndDevice(ctx, data.RefreshToken, data.UserDevice)
	switch {
	case errors.Is(err, le.ErrSessionNotFound):
		log.Error("%w: %w", le.ErrSessionNotFound, err)
		return jwtauth.TokenData{}, le.ErrSessionNotFound
	case errors.Is(err, le.ErrSessionExpired):
		log.Error("%w: %w", le.ErrSessionExpired, err)
		return jwtauth.TokenData{}, le.ErrSessionExpired
	case errors.Is(err, le.ErrUserDeviceNotFound):
		log.Error("%w: %w", le.ErrUserDeviceNotFound, err)
		return jwtauth.TokenData{}, le.ErrUserDeviceNotFound
	case err != nil:
		log.Error("%w: %w", le.ErrFailedToCheckSessionAndDevice, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	if err = u.deleteRefreshToken(ctx, data.RefreshToken); err != nil {
		log.Error("%w: %w", le.ErrFailedToDeleteRefreshToken, err)
		return jwtauth.TokenData{}, le.ErrInternalServerError
	}

	tokenData, err := u.CreateUserSession(ctx, log, session.UserID, data.UserDevice)
	if err != nil {
		return jwtauth.TokenData{}, err
	}

	log.Info("tokens created", slog.Any(key.UserID, session.UserID))

	return tokenData, nil
}

func (u *AuthUsecase) checkSessionAndDevice(ctx context.Context, refreshToken string, userDevice model.UserDeviceRequestData) (model.Session, error) {
	session, err := u.storage.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, le.ErrSessionNotFound) {
			return model.Session{}, le.ErrSessionNotFound
		}
		return model.Session{}, err
	}

	if session.IsExpired() {
		return model.Session{}, le.ErrSessionExpired
	}

	_, err = u.storage.GetUserDeviceID(ctx, session.UserID, userDevice.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			return model.Session{}, le.ErrUserDeviceNotFound
		}
		return model.Session{}, err
	}

	return session, nil
}

func (u *AuthUsecase) deleteRefreshToken(ctx context.Context, refreshToken string) error {
	return u.storage.DeleteRefreshToken(ctx, refreshToken)
}

func (u *AuthUsecase) LogoutUser(ctx context.Context, data model.UserDeviceRequestData) error {
	const method = "usecase.AuthUsecase.LogoutUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := jwtauth.GetUserID(ctx)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	log = log.With(slog.String(key.UserID, userID))

	// Check if the device exists
	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, data.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			return le.ErrUserDeviceNotFound
		}
		return err
	}

	return u.storage.DeleteSession(ctx, userID, deviceID)
}
