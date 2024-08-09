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
	"html/template"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/grpc/interceptor/requestid"
	"github.com/rshelekhov/sso/internal/lib/jwt"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
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
func (u *AuthUsecase) Login(ctx context.Context, data *model.UserRequestData) (model.AuthTokenData, error) {
	const method = "usecase.AuthUsecase.Login"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return model.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return model.AuthTokenData{}, err
	}

	user, err := u.storage.GetUserByEmail(ctx, data.Email, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err)
			return model.AuthTokenData{}, le.ErrUserNotFound
		}
		handleError(ctx, log, le.ErrFailedToGetUserByEmail, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, user, data.Password); err != nil {
		if errors.Is(err, le.ErrInvalidCredentials) {
			handleError(ctx, log, le.ErrInvalidCredentials, err, slog.Any(key.UserID, user.ID))
			return model.AuthTokenData{}, le.ErrInvalidCredentials
		}
		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, user.ID))
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	userDevice := model.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := model.AuthTokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err = u.CreateUserSession(ctx, log, user, userDevice)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, user.ID))
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return model.AuthTokenData{}, err
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
func (u *AuthUsecase) RegisterUser(ctx context.Context, data *model.UserRequestData, verifyEmailEndpoint string) (model.AuthTokenData, error) {
	const method = "usecase.AuthUsecase.RegisterUser"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return model.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return model.AuthTokenData{}, err
	}

	hash, err := jwt.PasswordHashBcrypt(
		data.Password,
		u.ts.PasswordHashCost,
		[]byte(u.ts.PasswordHashSalt),
	)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
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

	authTokenData := model.AuthTokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		userStatus, err := u.storage.GetUserStatus(ctx, user.Email)
		if err != nil {
			return err
		}

		switch userStatus {
		case "active":
			return le.ErrUserAlreadyExists
		case "soft_deleted":
			if err = u.storage.ReplaceSoftDeletedUser(ctx, user); err != nil {
				handleError(ctx, log, le.ErrFailedToCreateUser, err)
				return le.ErrInternalServerError
			}
		case "not_found":
			if err = u.storage.RegisterUser(ctx, user); err != nil {
				handleError(ctx, log, le.ErrFailedToCreateUser, err)
				return le.ErrInternalServerError
			}
		default:
			return fmt.Errorf("%s: unknown user status: %s", method, userStatus)
		}

		authTokenData, err = u.CreateUserSession(ctx, log, user, userDevice)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, user.ID))
			return le.ErrInternalServerError
		}

		verifyEmailData := model.TokenData{
			UserID:   user.ID,
			AppID:    data.AppID,
			Endpoint: verifyEmailEndpoint,
			Email:    data.Email,
			Type:     model.TokenTypeVerifyEmail,
		}

		tokenData, err := u.createToken(ctx, verifyEmailData, u.storage.CreateToken)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateToken, err)
			return le.ErrInternalServerError
		}

		if err = u.sendEmailWithToken(ctx, tokenData, model.EmailTemplateTypeVerifyEmail); err != nil {
			handleError(ctx, log, le.ErrFailedToSendVerificationEmail, err)
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return model.AuthTokenData{}, err
	}

	log.Info("user and tokens created, verification email sent",
		slog.String(key.UserID, user.ID),
	)

	return authTokenData, nil
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
	model.AuthTokenData,
	error,
) {
	const method = "usecase.AuthUsecase.CreateUserSession"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return model.AuthTokenData{}, err
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
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	kid, err := u.ts.GetKeyID(user.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetKeyID, err)
		return model.AuthTokenData{}, err
	}

	accessToken, err := u.ts.NewAccessToken(user.AppID, kid, additionalClaims)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateAccessToken, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	refreshToken, err := u.ts.NewRefreshToken()
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateRefreshToken, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
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
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	if err = u.updateLatestVisitedAt(ctx, deviceID, user.AppID, lastVisitedAt); err != nil {
		handleError(ctx, log, le.ErrFailedToUpdateLastVisitedAt, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	tokenData := model.AuthTokenData{
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

func (u *AuthUsecase) createToken(ctx context.Context, data model.TokenData, createTokenFunc func(ctx context.Context, data model.TokenData) error) (model.TokenData, error) {
	token, err := generateToken()
	if err != nil {
		return model.TokenData{}, le.ErrFailedToGenerateToken
	}

	data.Token = token
	data.CreatedAt = time.Now()
	data.ExpiresAt = time.Now().Add(24 * time.Hour)

	if err = createTokenFunc(ctx, data); err != nil {
		return model.TokenData{}, err
	}
	return data, nil
}

func (u *AuthUsecase) sendEmailWithToken(ctx context.Context, tokenData model.TokenData, templateType model.EmailTemplateType) error {
	subject := templateType.Subject()

	templatePath := filepath.Join(u.ms.GetTemplatesPath(), templateType.FileName())
	templatesBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}

	tmpl, err := template.New(templateType.String()).Parse(string(templatesBytes))
	if err != nil {
		return err
	}

	data := struct {
		Recipient string
		URL       string
	}{
		Recipient: tokenData.Email,
		URL:       fmt.Sprintf("%s%s", tokenData.Endpoint, tokenData.Token),
	}

	var body bytes.Buffer
	if err = tmpl.Execute(&body, data); err != nil {
		return err
	}

	return u.ms.SendHTML(ctx, subject, body.String(), tokenData.Email)
}

func (u *AuthUsecase) VerifyEmail(ctx context.Context, verificationToken string) error {
	const method = "usecase.AuthUsecase.VerifyEmail"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err := u.handleTokenProcessing(ctx, log, verificationToken, model.EmailTemplateTypeVerifyEmail)
		if err != nil {
			return err
		}

		if tokenData.Token == verificationToken {
			// It means that verification token was not expired and not generated new token with email resent
			if err = u.storage.MarkEmailVerified(ctx, tokenData.UserID, tokenData.AppID); err != nil {
				handleError(ctx, log, le.ErrFailedToMarkEmailVerified, err, slog.Any(key.Token, verificationToken))
				return le.ErrInternalServerError
			}
			log.Info("email verified", slog.String(key.UserID, tokenData.UserID))
			return nil
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err)
		return err
	}

	return nil
}

func (u *AuthUsecase) handleTokenProcessing(
	ctx context.Context,
	log *slog.Logger,
	token string,
	emailTemplateType model.EmailTemplateType,
) (model.TokenData, error) {
	tokenData, err := u.storage.GetTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, le.ErrTokenNotFound) {
			handleError(ctx, log, le.ErrTokenNotFound, err, slog.Any(key.Token, token))
			return model.TokenData{}, le.ErrTokenNotFound
		}
		handleError(ctx, log, le.ErrFailedToGetTokenData, err, slog.Any(key.Token, token))
		return model.TokenData{}, le.ErrInternalServerError
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		log.Info("token expired", slog.Any(key.UserID, tokenData.UserID), slog.Any(key.Token, tokenData.Token))

		if err = u.storage.DeleteToken(ctx, tokenData.Token); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteToken, err, slog.Any(key.Token, tokenData.Token))
			return model.TokenData{}, le.ErrInternalServerError
		}

		tokenData, err = u.createToken(ctx, tokenData, u.storage.CreateToken)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateToken, err)
			return model.TokenData{}, le.ErrInternalServerError
		}

		if err = u.sendEmailWithToken(ctx, tokenData, emailTemplateType); err != nil {
			handleError(ctx, log, le.ErrFailedToSendEmail, err)
			return model.TokenData{}, le.ErrInternalServerError
		}

		handleError(ctx, log, le.ErrTokenExpiredWithEmailResent, nil, slog.Any(key.UserID, tokenData.UserID))
		return tokenData, le.ErrTokenExpiredWithEmailResent
	}

	return tokenData, nil
}

func (u *AuthUsecase) ResetPassword(ctx context.Context, data *model.ResetPasswordRequestData, changePasswordEndpoint string) error {
	const method = "usecase.AuthUsecase.ResetPassword"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	user, err := u.storage.GetUserByEmail(ctx, data.Email, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.Email, data.Email))
			return le.ErrUserNotFound
		}
		handleError(ctx, u.log, le.ErrFailedToGetUserByEmail, err, slog.Any(key.Email, data.Email))
		return err
	}

	resetPasswordData := model.TokenData{
		UserID:   user.ID,
		AppID:    user.AppID,
		Endpoint: changePasswordEndpoint,
		Email:    user.Email,
		Type:     model.TokenTypeResetPassword,
	}

	tokenData, err := u.createToken(ctx, resetPasswordData, u.storage.CreateToken)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateResetPasswordToken, err)
		return le.ErrInternalServerError
	}

	if err = u.sendEmailWithToken(ctx, tokenData, model.EmailTemplateTypeResetPassword); err != nil {
		handleError(ctx, log, le.ErrFailedToSendEmail, err)
		return le.ErrInternalServerError
	}

	log.Info("reset password email sent",
		slog.String(key.UserID, user.ID),
		slog.String(key.Email, data.Email),
	)

	return nil
}

func (u *AuthUsecase) ChangePassword(ctx context.Context, data *model.ChangePasswordRequestData) error {
	const method = "usecase.AuthUsecase.ChangePassword"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return err
	}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err := u.handleTokenProcessing(ctx, log, data.ResetPasswordToken, model.EmailTemplateTypeResetPassword)
		if err != nil {
			return err
		}

		if tokenData.Token == data.ResetPasswordToken {
			// It means that reset password token was not expired and not generated new token with email resent
			userDataFromDB, err := u.storage.GetUserData(ctx, tokenData.UserID, data.AppID)
			if err != nil {
				handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, tokenData.UserID))
				return le.ErrInternalServerError
			}

			if err = u.checkPasswordHashAndUpdate(ctx, log, userDataFromDB, data); err != nil {
				return err
			}

			log.Info("password changed", slog.String(key.UserID, userDataFromDB.ID))
			return nil
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err)
		return err
	}

	return nil
}

func (u *AuthUsecase) checkPasswordHashAndUpdate(ctx context.Context, log *slog.Logger, userData model.User, reqData *model.ChangePasswordRequestData) error {
	err := u.checkPasswordHashMatch(userData.PasswordHash, reqData.UpdatedPassword)
	if err != nil && !errors.Is(err, le.ErrPasswordsDoNotMatch) {
		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, userData.ID))
		return le.ErrInternalServerError
	}
	if err == nil {
		handleError(ctx, log, le.ErrUpdatedPasswordMustNotMatchTheCurrent, nil, slog.Any(key.UserID, userData.ID))
		return le.ErrUpdatedPasswordMustNotMatchTheCurrent
	}

	updatedPassHash, err := jwt.PasswordHashBcrypt(reqData.UpdatedPassword, u.ts.PasswordHashCost, []byte(u.ts.PasswordHashSalt))
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err, slog.Any(key.UserID, userData.ID))
		return le.ErrInternalServerError
	}

	updatedUser := model.User{
		ID:           userData.ID,
		PasswordHash: updatedPassHash,
		AppID:        reqData.AppID,
		UpdatedAt:    time.Now(),
	}

	if err = u.storage.UpdateUser(ctx, updatedUser); err != nil {
		handleError(ctx, log, le.ErrFailedToUpdateUser, err, slog.Any(key.UserID, userData.ID))
		return le.ErrInternalServerError
	}

	return nil
}

func (u *AuthUsecase) LogoutUser(ctx context.Context, data model.UserDeviceRequestData, appID string) error {
	const method = "usecase.AuthUsecase.LogoutUser"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, appID); err != nil {
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

func (u *AuthUsecase) RefreshTokens(ctx context.Context, data *model.RefreshTokenRequestData) (model.AuthTokenData, error) {
	const method = "usecase.AuthUsecase.RefreshTokens"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return model.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return model.AuthTokenData{}, err
	}

	session, err := u.checkSessionAndDevice(ctx, data.RefreshToken, data.UserDevice)
	switch {
	case errors.Is(err, le.ErrSessionNotFound):
		handleError(ctx, log, le.ErrSessionNotFound, err)
		return model.AuthTokenData{}, le.ErrSessionNotFound
	case errors.Is(err, le.ErrSessionExpired):
		handleError(ctx, log, le.ErrSessionExpired, err)
		return model.AuthTokenData{}, le.ErrSessionExpired
	case errors.Is(err, le.ErrUserDeviceNotFound):
		handleError(ctx, log, le.ErrUserDeviceNotFound, err)
		return model.AuthTokenData{}, le.ErrUserDeviceNotFound
	case err != nil:
		handleError(ctx, log, le.ErrFailedToCheckSessionAndDevice, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	if err = u.deleteRefreshToken(ctx, data.RefreshToken); err != nil {
		handleError(ctx, log, le.ErrFailedToDeleteRefreshToken, err)
		return model.AuthTokenData{}, le.ErrInternalServerError
	}

	tokenData, err := u.CreateUserSession(ctx, log, model.User{ID: session.UserID, AppID: session.AppID}, data.UserDevice)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, session.UserID))
		return model.AuthTokenData{}, le.ErrInternalServerError
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

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
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

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return model.User{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
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

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
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
		// Check current password
		if err := u.checkPasswordHashMatch(userDataFromDB.PasswordHash, data.Password); err != nil {
			if errors.Is(err, le.ErrPasswordsDoNotMatch) {
				handleError(ctx, log, le.ErrCurrentPasswordIsIncorrect, err, slog.Any(key.UserID, userDataFromDB.ID))
				return le.ErrCurrentPasswordIsIncorrect
			}
			handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, userDataFromDB.ID))
			return le.ErrInternalServerError
		}

		// Check new password
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
		return le.ErrInternalServerError
	}

	err := u.storage.UpdateUser(ctx, updatedUser)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToUpdateUser, err, slog.Any(key.UserID, userDataFromDB.ID))
		return le.ErrInternalServerError
	}

	return nil
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

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
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
			if errors.Is(err, le.ErrUserNotFound) {
				handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
				return le.ErrUserNotFound
			}
			handleError(ctx, log, le.ErrFailedToDeleteUser, err, slog.Any(key.UserID, userID))
			return le.ErrFailedToDeleteUser
		}

		if err = u.storage.DeleteAllSessions(ctx, userID, data.AppID); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteAllSessions, err, slog.Any(key.UserID, userID))
			return le.ErrFailedToDeleteAllSessions
		}

		if err = u.storage.DeleteAllTokens(ctx, userID, data.AppID); err != nil {
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

// getReqID returns request ID from context
func (u *AuthUsecase) getReqID(ctx context.Context, method string) (string, error) {
	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return "", err
	}
	return reqID, nil
}

// validateAppID checks if appID exists in DB
func (u *AuthUsecase) validateAppID(ctx context.Context, log *slog.Logger, appID string) error {
	if err := u.storage.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, appID))
			return le.ErrAppIDDoesNotExist
		}
		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, appID))
		return err
	}
	return nil
}
