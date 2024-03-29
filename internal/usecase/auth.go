package usecase

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/jwt"
	"github.com/rshelekhov/sso/internal/lib/jwt/service"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"log/slog"
	"os"
	"time"
)

type AuthUsecase struct {
	log     *slog.Logger
	storage port.AuthStorage
	jwt     *service.TokenService
}

// NewAuthUsecase returns a new instance of the AuthUsecase usecase
func NewAuthUsecase(
	log *slog.Logger,
	storage port.AuthStorage,
	jwt *service.TokenService,
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
func (u *AuthUsecase) Login(ctx context.Context, data *model.UserRequestData) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.Login"

	log := u.log.With(
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	user, err := u.storage.GetUserByEmail(ctx, data.Email, data.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserByEmail, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, user, data.Password); err != nil {
		if errors.Is(err, le.ErrPasswordsDontMatch) {
			log.Error("%w: %w", le.ErrPasswordsDontMatch, err)
			return model.TokenData{}, le.ErrPasswordsDontMatch
		}
		log.Error("%w: %w", le.ErrFailedToCheckIfPasswordMatch, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := model.TokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err = u.CreateUserSession(ctx, log, user, userDevice)
		if err != nil {
			log.Error("%w: %w", le.ErrFailedToCreateUserSession, err)
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		return model.TokenData{}, err
	}

	log.Info("user authenticated, tokens created", slog.String(key.UserID, user.ID))

	return tokenData, nil
}

// verifyPassword checks if password is correct
func (u *AuthUsecase) verifyPassword(ctx context.Context, user model.User, password string) error {

	user, err := u.storage.GetUserData(ctx, user.ID, user.AppID)
	if err != nil {
		return err
	}

	matched, err := jwt.PasswordMatch(user.PasswordHash, password, []byte(u.jwt.PasswordHashSalt))
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
func (u *AuthUsecase) RegisterNewUser(ctx context.Context, data *model.UserRequestData) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.CreateUser"

	log := u.log.With(
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	hash, err := jwt.PasswordHashBcrypt(
		data.Password,
		u.jwt.PasswordHashCost,
		[]byte(u.jwt.PasswordHashSalt),
	)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGeneratePasswordHash, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	user := model.User{
		ID:           ksuid.New().String(),
		Email:        data.Email,
		PasswordHash: hash,
		AppID:        data.AppID,
		UpdatedAt:    time.Now(),
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := model.TokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		if err = u.storage.CreateUser(ctx, user); err != nil {
			// TODO: return a custom error

			if errors.Is(err, le.ErrEmailAlreadyTaken) {
				log.Error("%w: %w", le.ErrEmailAlreadyTaken, err)
				return le.ErrEmailAlreadyTaken
			}
			log.Error("%w: %w", le.ErrFailedToCreateUser, err)
			return le.ErrInternalServerError
		}

		tokenData, err = u.CreateUserSession(ctx, log, user, userDevice)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return model.TokenData{}, err
	}

	log.Info("user and tokens created", slog.String(key.UserID, user.ID))

	return tokenData, nil
}

// TODO: Move sessions from Postgres to Redis
// CreateUserSession creates new user session in the system and returns token
func (u *AuthUsecase) CreateUserSession(
	ctx context.Context,
	log *slog.Logger,
	user model.User,
	userDeviceRequest model.UserDeviceRequestData,
) (
	model.TokenData,
	error,
) {
	const method = "usecase.AuthUsecase.CreateUserSession"

	log = log.With(
		slog.String(key.Method, method),
		slog.String(key.UserID, user.ID),
	)

	additionalClaims := map[string]interface{}{
		key.ContextUserID: user.ID,
	}

	deviceID, err := u.getDeviceID(ctx, user.ID, user.AppID, userDeviceRequest)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetDeviceID, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	signKey, err := u.storage.GetAppSignKey(ctx, user.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetAppSignKey, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	accessToken, err := u.jwt.NewAccessToken(user.AppID, additionalClaims, signKey)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateAccessToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	refreshToken, err := u.jwt.NewRefreshToken()
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateRefreshToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	lastVisitedAt := time.Now()
	expiresAt := time.Now().Add(u.jwt.RefreshTokenTTL)

	session := model.Session{
		UserID:       user.ID,
		AppID:        user.AppID,
		DeviceID:     deviceID,
		RefreshToken: refreshToken,
		LastLoginAt:  lastVisitedAt,
		ExpiresAt:    expiresAt,
	}

	if err = u.storage.CreateUserSession(ctx, session); err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateUserSession, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.updateLastVisitedAt(ctx, deviceID, user.AppID, lastVisitedAt); err != nil {
		log.Error("%w: %w", le.ErrFailedToUpdateLastVisitedAt, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	additionalFields := map[string]string{key.UserID: user.ID}
	tokenData := model.TokenData{
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

func (u *AuthUsecase) getDeviceID(ctx context.Context, userID string, appID int32, userDeviceRequest model.UserDeviceRequestData) (string, error) {
	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, userDeviceRequest.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			return u.registerDevice(ctx, userID, appID, userDeviceRequest)
		}
		return "", err
	}

	return deviceID, nil
}

func (u *AuthUsecase) registerDevice(ctx context.Context, userID string, appID int32, userDeviceRequest model.UserDeviceRequestData) (string, error) {
	userDevice := model.UserDevice{
		ID:            ksuid.New().String(),
		UserID:        userID,
		AppID:         appID,
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

func (u *AuthUsecase) updateLastVisitedAt(ctx context.Context, deviceID string, appID int32, lastVisitedAt time.Time) error {
	return u.storage.UpdateLastLoginAt(ctx, deviceID, appID, lastVisitedAt)
}

func (u *AuthUsecase) LogoutUser(ctx context.Context, data model.UserDeviceRequestData, appID int32) error {
	const method = "usecase.AuthUsecase.LogoutUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := service.GetUserID(ctx)
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

	log.Info("user logged out", slog.String(key.DeviceID, deviceID))

	if err = u.storage.DeleteSession(ctx, userID, deviceID, appID); err != nil {
		log.Error("%w: %w", le.ErrFailedToDeleteSession, err)
		return le.ErrFailedToDeleteSession
	}

	return nil
}

func (u *AuthUsecase) RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.RefreshTokens"

	log := u.log.With(
		slog.String(key.Method, method),
	)

	session, err := u.checkSessionAndDevice(ctx, data.RefreshToken, data.UserDevice)
	switch {
	case errors.Is(err, le.ErrSessionNotFound):
		log.Error("%w: %w", le.ErrSessionNotFound, err)
		return model.TokenData{}, le.ErrSessionNotFound
	case errors.Is(err, le.ErrSessionExpired):
		log.Error("%w: %w", le.ErrSessionExpired, err)
		return model.TokenData{}, le.ErrSessionExpired
	case errors.Is(err, le.ErrUserDeviceNotFound):
		log.Error("%w: %w", le.ErrUserDeviceNotFound, err)
		return model.TokenData{}, le.ErrUserDeviceNotFound
	case err != nil:
		log.Error("%w: %w", le.ErrFailedToCheckSessionAndDevice, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.deleteRefreshToken(ctx, data.RefreshToken); err != nil {
		log.Error("%w: %w", le.ErrFailedToDeleteRefreshToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	tokenData, err := u.CreateUserSession(ctx, log, model.User{ID: session.UserID, AppID: session.AppID}, data.UserDevice)
	if err != nil {
		return model.TokenData{}, err
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

func (u *AuthUsecase) GetJWKS(ctx context.Context, request *model.JWKSRequestData) (model.JWKS, error) {
	const method = "usecase.AuthUsecase.GetJWKS"

	log := u.log.With(slog.String(key.Method, method))
	// Read the public key from the PEM file
	publicKey, err := u.GetPublicKeyFromPEM(request.AppID, u.jwt.KeysPath)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetJWKS, err)
		return model.JWKS{}, err
	}

	// Type assert the public key to JWK
	jwk, ok := publicKey.(*model.JWK)
	if !ok {
		log.Error("%w: %w", le.ErrFailedToTypeAssertJWK, err)
		return model.JWKS{}, le.ErrFailedToTypeAssertJWK
	}

	// Construct a JWKS with the JWK
	jwks := model.JWKS{
		Keys: []model.JWK{*jwk},
	}

	// Convert Keys slice to a map with Kid as key
	jwksMap := make(map[string]model.JWK)
	for _, key := range jwks.Keys {
		jwksMap[key.Kid] = key
	}

	log.Info("JWKS retrieved")

	return jwks, nil
}

func (u *AuthUsecase) GetPublicKeyFromPEM(appID int32, keysPath string) (interface{}, error) {
	const method = "usecase.AuthUsecase.GetPublicKeyFromPEM"

	log := u.log.With(slog.String(key.Method, method))

	// Construct the complete file path based on the AppID and provided keysPath
	filePath := fmt.Sprintf("%s/app_%d_public.pem", keysPath, appID)

	// Read the public key from the PEM file
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToReadFile, err)
		return model.JWKS{}, err
	}

	// Decode the PEM data to get the public key
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Error("%w: %w", le.ErrFailedToDecodePEM, err)
		return nil, le.ErrFailedToDecodePEM
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToParsePKIXPublicKey, err)
		return nil, le.ErrFailedToParsePKIXPublicKey
	}

	return pub, nil
}

func (u *AuthUsecase) GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error) {
	const method = "usecase.AuthUsecase.GetUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := service.GetUserID(ctx)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserIDFromToken, err)
		return model.User{}, le.ErrFailedToGetUserIDFromToken
	}

	log = log.With(slog.String(key.UserID, userID))

	user, err := u.storage.GetUserByID(ctx, userID, data.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUser, err)
		return model.User{}, le.ErrFailedToGetUser
	}

	log.Info("user found by ID")

	return user, nil
}

func (u *AuthUsecase) UpdateUser(ctx context.Context, data *model.UserRequestData) error {
	const method = "usecase.AuthUsecase.UpdateUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := service.GetUserID(ctx)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	log = log.With(slog.String(key.UserID, userID))

	currentUser, err := u.storage.GetUserData(ctx, userID, data.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUser, err)
		return le.ErrFailedToGetUser
	}

	hash, err := jwt.PasswordHashBcrypt(
		data.Password,
		u.jwt.PasswordHashCost,
		[]byte(u.jwt.PasswordHashSalt),
	)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGeneratePasswordHash, err)
		return le.ErrInternalServerError
	}

	updatedUser := model.User{
		ID:           currentUser.ID,
		Email:        data.Email,
		PasswordHash: hash,
		AppID:        data.AppID,
		UpdatedAt:    time.Now(),
	}

	emailChanged := updatedUser.Email != "" && updatedUser.Email != currentUser.Email
	passwordChanged := updatedUser.PasswordHash != ""

	if !emailChanged && !passwordChanged {
		return le.ErrNoChangesDetected
	}

	if err = u.storage.CheckEmailUniqueness(ctx, updatedUser); err != nil {
		return err
	}

	if data.Password != "" {
		if err = u.checkPassword(currentUser.PasswordHash, data.Password); err != nil {
			log.Error("%w: %w", le.ErrFailedToGeneratePasswordHash, err)
			return le.ErrInternalServerError
		}
	}

	return u.storage.UpdateUser(ctx, updatedUser)
}

func (u *AuthUsecase) checkPassword(currentPasswordHash, passwordFromRequest string) error {
	updatedPasswordHash, err := jwt.PasswordHashBcrypt(
		passwordFromRequest,
		u.jwt.PasswordHashCost,
		[]byte(u.jwt.PasswordHashSalt),
	)
	if err != nil {
		return err
	}

	if currentPasswordHash != updatedPasswordHash {
		return le.ErrNoPasswordChangesDetected
	}

	return nil
}

func (u *AuthUsecase) DeleteUser(ctx context.Context, data *model.UserRequestData) error {
	const method = "usecase.AuthUsecase.DeleteUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := service.GetUserID(ctx)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	log = log.With(slog.String(key.UserID, userID))

	// TODO: add transaction here

	user := model.User{
		ID:        userID,
		DeletedAt: time.Now(),
	}

	if err = u.storage.DeleteUser(ctx, user); err != nil {
		log.Error("%w: %w", le.ErrFailedToDeleteUser, err)
		return le.ErrFailedToDeleteUser
	}

	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, data.UserDevice.UserAgent)
	if err != nil {
		log.Error("%w: %w", le.ErrUserDeviceNotFound, err)
		return le.ErrUserDeviceNotFound
	}

	if err = u.storage.DeleteSession(ctx, userID, deviceID, data.AppID); err != nil {
		log.Error("%w: %w", le.ErrFailedToDeleteSession, err)
		return le.ErrFailedToDeleteSession
	}

	return nil
}
