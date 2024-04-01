package usecase

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/jwt"
	"github.com/rshelekhov/sso/internal/lib/jwt/service"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"log/slog"
	"math/big"
	"time"
)

type AuthUsecase struct {
	log     *slog.Logger
	storage port.AuthStorage
	ts      *service.TokenService
}

// NewAuthUsecase returns a new instance of the AuthUsecase usecase
func NewAuthUsecase(
	log *slog.Logger,
	storage port.AuthStorage,
	ts *service.TokenService,
) *AuthUsecase {
	return &AuthUsecase{
		log:     log,
		storage: storage,
		ts:      ts,
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
		if errors.Is(err, le.ErrUserNotFound) {
			log.Error("%w: %w", le.ErrUserNotFound, err)
			return model.TokenData{}, le.ErrUserNotFound
		}
		log.Error("%w: %w", le.ErrFailedToGetUserByEmail, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, user, data.Password); err != nil {
		if errors.Is(err, le.ErrInvalidCredentials) {
			log.Error("%w: %w", le.ErrInvalidCredentials, err)
			return model.TokenData{}, le.ErrInvalidCredentials
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

	matched, err := jwt.PasswordMatch(user.PasswordHash, password, []byte(u.ts.PasswordHashSalt))
	if err != nil {
		return err
	}

	if !matched {
		return le.ErrInvalidCredentials
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
		u.ts.PasswordHashCost,
		[]byte(u.ts.PasswordHashSalt),
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

	log.Info("user data before passing into storage",
		slog.String(key.UserID, user.ID),
		slog.String(key.Email, user.Email),
		slog.String(key.PasswordHash, user.PasswordHash),
		slog.Int(key.AppID, int(user.AppID)),
		slog.Time(key.UpdatedAt, user.UpdatedAt),
	)

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := model.TokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		if err = u.storage.CreateUser(ctx, user); err != nil {
			// TODO: return a custom error

			if errors.Is(err, le.ErrUserAlreadyExists) {
				log.Error("%w: %w", le.ErrUserAlreadyExists, err)
				return le.ErrUserAlreadyExists
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
		key.Issuer:       u.ts.Issuer,
		key.UserID:       user.ID,
		key.Email:        user.Email,
		key.AppID:        user.AppID,
		key.ExpirationAt: time.Now().Add(u.ts.AccessTokenTTL).Unix(),
	}

	deviceID, err := u.getDeviceID(ctx, user.ID, user.AppID, userDeviceRequest)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetDeviceID, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	accessToken, err := u.ts.NewAccessToken(user.AppID, additionalClaims)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateAccessToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	refreshToken, err := u.ts.NewRefreshToken()
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToCreateRefreshToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	lastVisitedAt := time.Now()
	expiresAt := time.Now().Add(u.ts.RefreshTokenTTL)

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

	kid, err := u.ts.GetKeyID(user.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetKeyID, err)
		return model.TokenData{}, err
	}

	// TODO: check and remove this commented code
	// additionalFields := map[string]string{key.UserID: user.ID}
	tokenData := model.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Kid:          kid,
		Domain:       u.ts.RefreshTokenCookieDomain,
		Path:         u.ts.RefreshTokenCookiePath,
		ExpiresAt:    expiresAt,
		HTTPOnly:     true,
		// AdditionalFields: additionalFields,
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

	userID, err := u.ts.GetUserID(ctx, appID, key.UserID)
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
	publicKey, err := u.ts.GetPublicKey(request.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetJWKS, err)
		return model.JWKS{}, err
	}

	kid, err := u.ts.GetKeyID(request.AppID)
	if err != nil {
		log.Error("%w: %w", le.ErrFailedToGetKeyID, err)
		return model.JWKS{}, err
	}

	jwk := model.JWK{
		Alg: u.ts.SigningMethod,
		Use: "alg",
		Kid: kid,
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		p := pub.Curve.Params()
		jwk.Kty = "EC"
		jwk.Crv = p.Name
		jwk.X = base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	default:
		return model.JWKS{}, le.ErrFailedToGetJWKS
	}

	// Construct a JWKS with the JWK
	jwksSlice := []model.JWK{jwk}
	jwks := constructJWKS(jwksSlice...)

	log.Info("JWKS retrieved")

	return jwks, nil
}

func constructJWKS(jwks ...model.JWK) model.JWKS {
	return model.JWKS{Keys: jwks}
}

func (u *AuthUsecase) GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error) {
	const method = "usecase.AuthUsecase.GetUser"

	log := u.log.With(slog.String(key.Method, method))

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
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

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
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
		u.ts.PasswordHashCost,
		[]byte(u.ts.PasswordHashSalt),
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
		u.ts.PasswordHashCost,
		[]byte(u.ts.PasswordHashSalt),
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

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
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
