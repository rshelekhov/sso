package usecase

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/grpc/interceptor/requestid"
	"github.com/rshelekhov/sso/internal/lib/jwt"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"html/template"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type AuthUsecase struct {
	log     *slog.Logger
	storage port.AuthStorage
	ts      *jwtoken.Service
	ms      port.MailService
}

// NewAuthUsecase returns a new instance of the AuthUsecase usecase
func NewAuthUsecase(
	log *slog.Logger,
	storage port.AuthStorage,
	ts *jwtoken.Service,
	ms port.MailService,
) *AuthUsecase {
	return &AuthUsecase{
		log:     log,
		storage: storage,
		ts:      ts,
		ms:      ms,
	}
}

// Login checks if user with given credentials exists in the system
func (u *AuthUsecase) Login(ctx context.Context, data *model.UserRequestData) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.Login"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.TokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return model.TokenData{}, le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return model.TokenData{}, err
	}

	user, err := u.storage.GetUserByEmail(ctx, data.Email, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err)
			return model.TokenData{}, le.ErrUserNotFound
		}
		handleError(ctx, log, le.ErrFailedToGetUserByEmail, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, user, data.Password); err != nil {
		if errors.Is(err, le.ErrInvalidCredentials) {
			handleError(ctx, log, le.ErrInvalidCredentials, err, slog.Any(key.UserID, user.ID))
			return model.TokenData{}, le.ErrInvalidCredentials
		}
		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, user.ID))
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
			handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, user.ID))
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return model.TokenData{}, err
	}

	log.Info("user authenticated, tokens created",
		slog.String(key.UserID, user.ID),
	)

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

// RegisterUser creates new user in the system and returns jwtoken
func (u *AuthUsecase) RegisterUser(ctx context.Context, data *model.UserRequestData, verifyEmailEndpoint string) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.RegisterUser"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.TokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return model.TokenData{}, le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return model.TokenData{}, err
	}

	hash, err := jwt.PasswordHashBcrypt(
		data.Password,
		u.ts.PasswordHashCost,
		[]byte(u.ts.PasswordHashSalt),
	)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	now := time.Now()
	user := model.User{
		ID:           ksuid.New().String(),
		Email:        data.Email,
		PasswordHash: hash,
		AppID:        data.AppID,
		Verified:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := model.TokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		if err = u.storage.RegisterUser(ctx, user); err != nil {
			if errors.Is(err, le.ErrUserAlreadyExists) {
				handleError(ctx, log, le.ErrUserAlreadyExists, err, slog.Any(key.Email, data.Email))
				return le.ErrUserAlreadyExists
			}
			handleError(ctx, log, le.ErrFailedToCreateUser, err)
			return le.ErrInternalServerError
		}

		tokenData, err = u.CreateUserSession(ctx, log, user, userDevice)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, user.ID))
			return le.ErrInternalServerError
		}

		verificationToken, err := u.createEmailVerificationToken(ctx, u.log, user.ID, user.AppID, user.Email, verifyEmailEndpoint)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateEmailVerificationToken, err)
			return le.ErrInternalServerError
		}

		if err = u.sendVerificationEmail(ctx, verifyEmailEndpoint, data.Email, verificationToken); err != nil {
			handleError(ctx, log, le.ErrFailedToSendVerificationEmail, err)
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return model.TokenData{}, err
	}

	log.Info("user and tokens created, verification email sent",
		slog.String(key.UserID, user.ID),
	)

	return tokenData, nil
}

func generateToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

// TODO: Move sessions from Postgres to Redis

// CreateUserSession creates new user session in the system and returns jwtoken
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

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.TokenData{}, err
	}

	log = log.With(
		slog.String(key.RequestID, reqID),
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
		handleError(ctx, log, le.ErrFailedToGetDeviceID, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	kid, err := u.ts.GetKeyID(user.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetKeyID, err)
		return model.TokenData{}, err
	}

	accessToken, err := u.ts.NewAccessToken(user.AppID, kid, additionalClaims)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateAccessToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	refreshToken, err := u.ts.NewRefreshToken()
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateRefreshToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	lastVisitedAt := time.Now()
	expiresAt := time.Now().Add(u.ts.RefreshTokenTTL)

	session := model.Session{
		UserID:        user.ID,
		AppID:         user.AppID,
		DeviceID:      deviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: lastVisitedAt,
		ExpiresAt:     expiresAt,
	}

	if err = u.storage.CreateUserSession(ctx, session); err != nil {
		handleError(ctx, log, le.ErrFailedToCreateUserSession, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.updateLatestVisitedAt(ctx, deviceID, user.AppID, lastVisitedAt); err != nil {
		handleError(ctx, log, le.ErrFailedToUpdateLastVisitedAt, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	tokenData := model.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Domain:       u.ts.RefreshTokenCookieDomain,
		Path:         u.ts.RefreshTokenCookiePath,
		ExpiresAt:    expiresAt,
		HTTPOnly:     true,
	}

	log.Info("user session created")

	return tokenData, nil
}

func (u *AuthUsecase) getDeviceID(ctx context.Context, userID, appID string, userDeviceRequest model.UserDeviceRequestData) (string, error) {
	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, userDeviceRequest.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			return u.registerDevice(ctx, userID, appID, userDeviceRequest)
		}
		return "", err
	}

	return deviceID, nil
}

func (u *AuthUsecase) registerDevice(ctx context.Context, userID, appID string, userDeviceRequest model.UserDeviceRequestData) (string, error) {
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
		return "", err
	}

	return userDevice.ID, nil
}

func (u *AuthUsecase) updateLatestVisitedAt(ctx context.Context, deviceID, appID string, lastVisitedAt time.Time) error {
	return u.storage.UpdateLatestVisitedAt(ctx, deviceID, appID, lastVisitedAt)
}

func (u *AuthUsecase) createEmailVerificationToken(ctx context.Context, log *slog.Logger, userID, appID, email, verifyEmailEndpoint string) (string, error) {
	token, err := generateToken()
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGenerateEmailVerificationToken, err)
		return "", le.ErrInternalServerError
	}

	data := model.EmailVerificationData{
		VerificationToken: token,
		UserID:            userID,
		AppID:             appID,
		Endpoint:          verifyEmailEndpoint,
		Email:             email,
		Type:              model.TokenTypeVerifyEmail,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(24 * time.Hour),
	}

	if err = u.storage.CreateEmailVerificationToken(ctx, data); err != nil {
		return "", err
	}
	return token, nil
}

func (u *AuthUsecase) sendVerificationEmail(ctx context.Context, endpoint, recipient, token string) error {
	subject := "Confirmation instructions"

	templatePath := filepath.Join(u.ms.GetTemplatesPath(), model.EmailTemplateTypeVerifyEmail.FileName())
	templatesBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}

	tmpl, err := template.New(model.EmailTemplateTypeVerifyEmail.String()).Parse(string(templatesBytes))
	if err != nil {
		return err
	}

	data := struct {
		Recipient string
		URL       string
	}{
		Recipient: recipient,
		URL:       fmt.Sprintf("%s%s", endpoint, token),
	}

	var body bytes.Buffer
	if err = tmpl.Execute(&body, data); err != nil {
		return err
	}

	return u.ms.SendHTML(ctx, subject, body.String(), recipient)
}

func (u *AuthUsecase) VerifyEmail(ctx context.Context, verificationToken string) error {
	const method = "usecase.AuthUsecase.VerifyEmail"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	var data model.EmailVerificationData

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		data, err = u.storage.GetEmailVerificationData(ctx, verificationToken)
		if err != nil {
			if errors.Is(err, le.ErrEmailVerificationTokenNotFound) {
				handleError(ctx, log, le.ErrEmailVerificationTokenNotFound, err, slog.Any(key.VerificationToken, verificationToken))
				return le.ErrEmailVerificationTokenNotFound
			}
			handleError(ctx, log, le.ErrFailedToGetEmailVerificationToken, err, slog.Any(key.VerificationToken, verificationToken))
			return le.ErrInternalServerError
		}

		if data.ExpiresAt.Before(time.Now()) {
			log.Info("verification token expired", slog.Any(key.UserID, data.UserID), slog.Any(key.VerificationToken, verificationToken))

			if err = u.storage.DeleteEmailVerificationToken(ctx, verificationToken); err != nil {
				handleError(ctx, log, le.ErrFailedToDeleteVerificationToken, err, slog.Any(key.VerificationToken, verificationToken))
				return le.ErrInternalServerError
			}

			newToken, err := u.createEmailVerificationToken(ctx, u.log, data.UserID, data.AppID, data.Email, data.Endpoint)
			if err != nil {
				handleError(ctx, log, le.ErrFailedToCreateEmailVerificationToken, err)
				return le.ErrInternalServerError
			}

			err = u.sendVerificationEmail(ctx, data.Endpoint, data.Email, newToken)
			if err != nil {
				handleError(ctx, log, le.ErrFailedToSendVerificationEmail, err, slog.Any(key.VerificationToken, verificationToken))
				return le.ErrInternalServerError
			}
			return le.ErrVerificationTokenExpiredWithEmailResent
		} else {
			if err = u.storage.MarkEmailVerified(ctx, data); err != nil {
				handleError(ctx, log, le.ErrFailedToMarkEmailVerified, err, slog.Any(key.VerificationToken, verificationToken))
				return le.ErrInternalServerError
			}
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err)
		return err
	}

	log.Info("email verified",
		slog.String(key.UserID, data.UserID),
	)

	return nil
}

func (u *AuthUsecase) LogoutUser(ctx context.Context, data model.UserDeviceRequestData, appID string) error {
	const method = "usecase.AuthUsecase.LogoutUser"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, appID))
			return le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, appID))
		return err
	}

	userID, err := u.ts.GetUserID(ctx, appID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	// Check if the device exists
	deviceID, err := u.storage.GetUserDeviceID(ctx, userID, data.UserAgent)
	if err != nil {
		if errors.Is(err, le.ErrUserDeviceNotFound) {
			handleError(ctx, log, le.ErrUserDeviceNotFound, err)
			return le.ErrUserDeviceNotFound
		}
		handleError(ctx, log, le.ErrFailedToGetDeviceID, err)
		return err
	}

	log.Info("user logged out",
		slog.String(key.UserID, userID),
		slog.String(key.DeviceID, deviceID),
	)

	if err = u.storage.DeleteSession(ctx, userID, deviceID, appID); err != nil {
		handleError(ctx, log, le.ErrFailedToDeleteSession, err)
		return le.ErrFailedToDeleteSession
	}

	return nil
}

func (u *AuthUsecase) RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (model.TokenData, error) {
	const method = "usecase.AuthUsecase.RefreshTokens"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.TokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return model.TokenData{}, le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return model.TokenData{}, err
	}

	session, err := u.checkSessionAndDevice(ctx, data.RefreshToken, data.UserDevice)
	switch {
	case errors.Is(err, le.ErrSessionNotFound):
		handleError(ctx, log, le.ErrSessionNotFound, err)
		return model.TokenData{}, le.ErrSessionNotFound
	case errors.Is(err, le.ErrSessionExpired):
		handleError(ctx, log, le.ErrSessionExpired, err)
		return model.TokenData{}, le.ErrSessionExpired
	case errors.Is(err, le.ErrUserDeviceNotFound):
		handleError(ctx, log, le.ErrUserDeviceNotFound, err)
		return model.TokenData{}, le.ErrUserDeviceNotFound
	case err != nil:
		handleError(ctx, log, le.ErrFailedToCheckSessionAndDevice, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	if err = u.deleteRefreshToken(ctx, data.RefreshToken); err != nil {
		handleError(ctx, log, le.ErrFailedToDeleteRefreshToken, err)
		return model.TokenData{}, le.ErrInternalServerError
	}

	tokenData, err := u.CreateUserSession(ctx, log, model.User{ID: session.UserID, AppID: session.AppID}, data.UserDevice)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, session.UserID))
		return model.TokenData{}, le.ErrInternalServerError
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

func (u *AuthUsecase) GetJWKS(ctx context.Context, data *model.JWKSRequestData) (model.JWKS, error) {
	const method = "usecase.AuthUsecase.GetJWKS"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.JWKS{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return model.JWKS{}, le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return model.JWKS{}, err
	}

	// Read the public key from the PEM file
	publicKey, err := u.ts.GetPublicKey(data.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetJWKS, err)
		return model.JWKS{}, err
	}

	kid, err := u.ts.GetKeyID(data.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetJWKS, err)
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
	jwks := u.constructJWKS(jwksSlice...)

	log.Info("JWKS retrieved")

	return jwks, nil
}

func (u *AuthUsecase) constructJWKS(jwks ...model.JWK) model.JWKS {
	return model.JWKS{
		Keys: jwks,
		TTL:  u.ts.JWKSetTTL,
	}
}

func (u *AuthUsecase) GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error) {
	const method = "usecase.AuthUsecase.GetUser"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return model.User{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return model.User{}, le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return model.User{}, err
	}

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return model.User{}, le.ErrFailedToGetUserIDFromToken
	}

	user, err := u.storage.GetUserByID(ctx, userID, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
			return model.User{}, le.ErrUserNotFound
		}
		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
		return model.User{}, le.ErrFailedToGetUser
	}

	log.Info("user found by ID", slog.String(key.UserID, userID))

	return user, nil
}

func (u *AuthUsecase) UpdateUser(ctx context.Context, data *model.UserRequestData) error {
	const method = "usecase.AuthUsecase.UpdateUser"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return err
	}

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	userDataFromDB, err := u.storage.GetUserData(ctx, userID, data.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
		return le.ErrFailedToGetUser
	}

	if err = updateUserFields(u, ctx, data, userDataFromDB, log); err != nil {
		return err
	}

	log.Info("user updated", slog.String(key.UserID, userID))

	return nil
}

func updateUserFields(u *AuthUsecase, ctx context.Context, data *model.UserRequestData, userDataFromDB model.User, log *slog.Logger) error {
	updatedUser := model.User{
		ID:        userDataFromDB.ID,
		Email:     data.Email,
		AppID:     data.AppID,
		UpdatedAt: time.Now(),
	}

	if data.UpdatedPassword != "" {
		if err := u.checkPasswordHashMatch(userDataFromDB.PasswordHash, data.Password); err != nil {
			if errors.Is(err, le.ErrPasswordsDoNotMatch) {
				handleError(ctx, log, le.ErrCurrentPasswordIsIncorrect, err, slog.Any(key.UserID, userDataFromDB.ID))
				return le.ErrCurrentPasswordIsIncorrect
			}
			handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, userDataFromDB.ID))
			return le.ErrInternalServerError
		}

		if err := u.checkPasswordHashMatch(userDataFromDB.PasswordHash, data.UpdatedPassword); err == nil {
			handleError(ctx, log, le.ErrNoPasswordChangesDetected, nil, slog.Any(key.UserID, userDataFromDB.ID))
			return le.ErrNoPasswordChangesDetected
		}

		updatedPassHash, err := jwt.PasswordHashBcrypt(
			data.UpdatedPassword,
			u.ts.PasswordHashCost,
			[]byte(u.ts.PasswordHashSalt),
		)

		if err != nil {
			handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err, slog.Any(key.UserID, userDataFromDB.ID))
			return le.ErrInternalServerError
		}

		updatedUser.PasswordHash = updatedPassHash
	}

	emailChanged := updatedUser.Email != "" && updatedUser.Email != userDataFromDB.Email

	if !emailChanged {
		handleError(ctx, log, le.ErrNoEmailChangesDetected, nil, slog.Any(key.UserID, userDataFromDB.ID))
		return le.ErrNoEmailChangesDetected
	}

	if err := u.storage.CheckEmailUniqueness(ctx, updatedUser); err != nil {
		if errors.Is(err, le.ErrEmailAlreadyTaken) {
			handleError(ctx, log, le.ErrEmailAlreadyTaken, err,
				slog.Any(key.UserID, userDataFromDB.ID),
				slog.String(key.Email, updatedUser.Email))
			return le.ErrEmailAlreadyTaken
		}
		handleError(ctx, log, le.ErrFailedToCheckEmailUniqueness, err, slog.Any(key.UserID, userDataFromDB.ID))
		return err
	}

	return u.storage.UpdateUser(ctx, updatedUser)
}

func (u *AuthUsecase) checkPasswordHashMatch(hash string, password string) error {
	matched, err := jwt.PasswordMatch(hash, password, []byte(u.ts.PasswordHashSalt))
	if err != nil {
		return err
	}

	if !matched {
		return le.ErrPasswordsDoNotMatch
	}

	return nil
}

func (u *AuthUsecase) DeleteUser(ctx context.Context, data *model.UserRequestData) error {
	const method = "usecase.AuthUsecase.DeleteUser"

	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return err
	}

	userID, err := u.ts.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	user := model.User{
		ID:        userID,
		AppID:     data.AppID,
		DeletedAt: time.Now(),
	}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		if err = u.storage.DeleteUser(ctx, user); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteUser, err, slog.Any(key.UserID, userID))
			return le.ErrFailedToDeleteUser
		}

		if err = u.storage.DeleteAllSessions(ctx, userID, data.AppID); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteAllSessions, err, slog.Any(key.UserID, userID))
			return le.ErrFailedToDeleteAllSessions
		}

		if err = u.storage.DeleteTokens(ctx, userID, data.AppID); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteTokens, err, slog.Any(key.UserID, userID))
			return le.ErrFailedToDeleteTokens
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return err
	}

	log.Info("user soft-deleted", slog.String(key.UserID, userID))

	return nil
}
