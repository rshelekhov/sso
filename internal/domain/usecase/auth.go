package auth

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
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
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
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
)

type SessionService interface {
	CreateUserSession(ctx context.Context, user entity.User, userDeviceRequest entity.UserDeviceRequestData) (entity.AuthTokenData, error)
	CheckSessionAndDevice(ctx context.Context, refreshToken string, userDevice entity.UserDeviceRequestData) (entity.Session, error)
	GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	DeleteSession(ctx context.Context, userID, deviceID, appID string) error
	DeleteAllUserSessions(ctx context.Context, user entity.User) error
}

type MailService interface {
	SendPlainText(ctx context.Context, subject, body, recipient string) error
	SendHTML(ctx context.Context, subject, html, recipient string) error
	GetTemplatesPath() string
}

type Usecase struct {
	log            *slog.Logger
	storage        port.AuthStorage
	appValidator   appvalidator.Validator
	tokenService   *jwtoken.Service
	sessionService SessionService
	mailService    MailService
}

func NewAuthUsecase(
	log *slog.Logger,
	storage port.AuthStorage,
	av appvalidator.Validator,
	ts *jwtoken.Service,
	ss SessionService,
	ms MailService,
) *Usecase {
	return &Usecase{
		log:            log,
		storage:        storage,
		appValidator:   av,
		tokenService:   ts,
		sessionService: ss,
		mailService:    ms,
	}
}

//var (
//	ErrFailedToCreateUserSession     = errors.New("failed to create user session")
//	ErrSessionNotFound               = errors.New("session not found")
//	ErrSessionExpired                = errors.New("session expired")
//	ErrUserDeviceNotFound            = errors.New("user device not found")
//	ErrFailedToCheckSessionAndDevice = errors.New("failed to check session and device")
//	ErrFailedToDeleteRefreshToken    = errors.New("failed to delete refresh token")
//	ErrFailedToGetDeviceID           = errors.New("failed to get device ID")
//	ErrFailedToDeleteSession         = errors.New("failed to delete session")
//)

// Login checks if user with given credentials exists in the system
func (u *Usecase) Login(ctx context.Context, data *entity.UserRequestData) (entity.AuthTokenData, error) {
	const method = "usecase.Usecase.Login"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return entity.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return entity.AuthTokenData{}, err
	}

	user, err := u.storage.GetUserByEmail(ctx, data.Email, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err)
			return entity.AuthTokenData{}, le.ErrUserNotFound
		}

		handleError(ctx, log, le.ErrFailedToGetUserByEmail, err)
		return entity.AuthTokenData{}, le.ErrInternalServerError
	}

	if err = u.verifyPassword(ctx, user, data.Password); err != nil {
		if errors.Is(err, le.ErrInvalidCredentials) {
			handleError(ctx, log, le.ErrInvalidCredentials, err, slog.Any(key.UserID, user.ID))
			return entity.AuthTokenData{}, le.ErrInvalidCredentials
		}

		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, user.ID))
		return entity.AuthTokenData{}, le.ErrInternalServerError
	}

	userDevice := entity.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	tokenData := entity.AuthTokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err = u.sessionService.CreateUserSession(ctx, user, userDevice)
		if err != nil {
			handleError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any("userID", user.ID))
			return err
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return entity.AuthTokenData{}, err
	}

	log.Info("user authenticated, tokens created",
		slog.String(key.UserID, user.ID),
	)

	return tokenData, nil
}

// verifyPassword checks if password is correct
func (u *Usecase) verifyPassword(ctx context.Context, user entity.User, password string) error {
	user, err := u.storage.GetUserData(ctx, user.ID, user.AppID)
	if err != nil {
		return err
	}

	matched, err := jwt.PasswordMatch(user.PasswordHash, password, u.tokenService.PasswordHashParams)
	if err != nil {
		return err
	}

	if !matched {
		return le.ErrInvalidCredentials
	}

	return nil
}

// RegisterUser creates new user in the system and returns jwtoken
func (u *Usecase) RegisterUser(ctx context.Context, data *entity.UserRequestData, verifyEmailEndpoint string) (entity.AuthTokenData, error) {
	const method = "usecase.Usecase.RegisterUser"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return entity.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
		slog.String(key.Email, data.Email),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return entity.AuthTokenData{}, err
	}

	hash, err := jwt.PasswordHash(data.Password, u.tokenService.PasswordHashParams)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err)
		return entity.AuthTokenData{}, le.ErrInternalServerError
	}

	now := time.Now()
	user := entity.User{
		ID:           ksuid.New().String(),
		Email:        data.Email,
		PasswordHash: hash,
		AppID:        data.AppID,
		Verified:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	userDevice := entity.UserDeviceRequestData{
		UserAgent: data.UserDevice.UserAgent,
		IP:        data.UserDevice.IP,
	}

	authTokenData := entity.AuthTokenData{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		userStatus, err := u.storage.GetUserStatusByEmail(ctx, user.Email)
		if err != nil {
			return err
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			return le.ErrUserAlreadyExists
		case entity.UserStatusSoftDeleted.String():
			if err = u.storage.ReplaceSoftDeletedUser(ctx, user); err != nil {
				handleError(ctx, log, le.ErrFailedToCreateUser, err)
				return le.ErrInternalServerError
			}
		case entity.UserStatusNotFound.String():
			if err = u.storage.RegisterUser(ctx, user); err != nil {
				handleError(ctx, log, le.ErrFailedToCreateUser, err)
				return le.ErrInternalServerError
			}
		default:
			return fmt.Errorf("%s: unknown user status: %s", method, userStatus)
		}

		authTokenData, err = u.sessionService.CreateUserSession(ctx, user, userDevice)
		if err != nil {
			handleError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any(key.UserID, user.ID))
			return err
		}

		verifyEmailData := entity.TokenData{
			UserID:   user.ID,
			AppID:    data.AppID,
			Endpoint: verifyEmailEndpoint,
			Email:    data.Email,
			Type:     entity.TokenTypeVerifyEmail,
		}

		tokenData, err := u.createToken(ctx, verifyEmailData, u.storage.CreateToken)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateToken, err)
			return le.ErrInternalServerError
		}

		if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeVerifyEmail); err != nil {
			handleError(ctx, log, le.ErrFailedToSendVerificationEmail, err)
			return le.ErrInternalServerError
		}

		return nil
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return entity.AuthTokenData{}, err
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

func (u *Usecase) createToken(
	ctx context.Context,
	data entity.TokenData,
	createTokenFunc func(ctx context.Context, data entity.TokenData) error,
) (
	entity.TokenData,
	error,
) {
	token, err := generateToken()
	if err != nil {
		return entity.TokenData{}, le.ErrFailedToGenerateToken
	}

	data.Token = token
	data.CreatedAt = time.Now()
	data.ExpiresAt = time.Now().Add(24 * time.Hour)

	if err = createTokenFunc(ctx, data); err != nil {
		return entity.TokenData{}, err
	}
	return data, nil
}

func (u *Usecase) sendEmailWithToken(ctx context.Context, tokenData entity.TokenData, templateType entity.EmailTemplateType) error {
	subject := templateType.Subject()

	templatePath := filepath.Join(u.mailService.GetTemplatesPath(), templateType.FileName())
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

	return u.mailService.SendHTML(ctx, subject, body.String(), tokenData.Email)
}

func (u *Usecase) VerifyEmail(ctx context.Context, verificationToken string) error {
	const method = "usecase.Usecase.VerifyEmail"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err := u.handleTokenProcessing(ctx, log, verificationToken, entity.EmailTemplateTypeVerifyEmail)
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

func (u *Usecase) handleTokenProcessing(
	ctx context.Context,
	log *slog.Logger,
	token string,
	emailTemplateType entity.EmailTemplateType,
) (entity.TokenData, error) {
	tokenData, err := u.storage.GetTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, le.ErrTokenNotFound) {
			handleError(ctx, log, le.ErrTokenNotFound, err, slog.Any(key.Token, token))
			return entity.TokenData{}, le.ErrTokenNotFound
		}

		handleError(ctx, log, le.ErrFailedToGetTokenData, err, slog.Any(key.Token, token))
		return entity.TokenData{}, le.ErrInternalServerError
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		log.Info("token expired",
			slog.Any(key.UserID, tokenData.UserID),
			slog.Any(key.Token, tokenData.Token))

		if err = u.storage.DeleteToken(ctx, tokenData.Token); err != nil {
			handleError(ctx, log, le.ErrFailedToDeleteToken, err, slog.Any(key.Token, tokenData.Token))
			return entity.TokenData{}, le.ErrInternalServerError
		}

		tokenData, err = u.createToken(ctx, tokenData, u.storage.CreateToken)
		if err != nil {
			handleError(ctx, log, le.ErrFailedToCreateToken, err)
			return entity.TokenData{}, le.ErrInternalServerError
		}

		if err = u.sendEmailWithToken(ctx, tokenData, emailTemplateType); err != nil {
			handleError(ctx, log, le.ErrFailedToSendEmail, err)
			return entity.TokenData{}, le.ErrInternalServerError
		}

		handleError(ctx, log, le.ErrTokenExpiredWithEmailResent, nil, slog.Any(key.UserID, tokenData.UserID))
		return tokenData, le.ErrTokenExpiredWithEmailResent
	}

	return tokenData, nil
}

func (u *Usecase) ResetPassword(ctx context.Context, data *entity.ResetPasswordRequestData, changePasswordEndpoint string) error {
	const method = "usecase.Usecase.ResetPassword"

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

	resetPasswordData := entity.TokenData{
		UserID:   user.ID,
		AppID:    user.AppID,
		Endpoint: changePasswordEndpoint,
		Email:    user.Email,
		Type:     entity.TokenTypeResetPassword,
	}

	tokenData, err := u.createToken(ctx, resetPasswordData, u.storage.CreateToken)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToCreateResetPasswordToken, err)
		return le.ErrInternalServerError
	}

	if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeResetPassword); err != nil {
		handleError(ctx, log, le.ErrFailedToSendEmail, err)
		return le.ErrInternalServerError
	}

	log.Info("reset password email sent",
		slog.String(key.UserID, user.ID),
		slog.String(key.Email, data.Email),
	)

	return nil
}

func (u *Usecase) ChangePassword(ctx context.Context, data *entity.ChangePasswordRequestData) error {
	const method = "usecase.Usecase.ChangePassword"

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
		tokenData, err := u.handleTokenProcessing(ctx, log, data.ResetPasswordToken, entity.EmailTemplateTypeResetPassword)
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

func (u *Usecase) checkPasswordHashAndUpdate(
	ctx context.Context,
	log *slog.Logger,
	userData entity.User,
	reqData *entity.ChangePasswordRequestData,
) error {
	err := u.checkPasswordHashMatch(userData.PasswordHash, reqData.UpdatedPassword)
	if err != nil && !errors.Is(err, le.ErrPasswordsDoNotMatch) {
		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, userData.ID))
		return le.ErrInternalServerError
	}
	if err == nil {
		handleError(ctx, log, le.ErrUpdatedPasswordMustNotMatchTheCurrent, nil, slog.Any(key.UserID, userData.ID))
		return le.ErrUpdatedPasswordMustNotMatchTheCurrent
	}

	updatedPassHash, err := jwt.PasswordHash(reqData.UpdatedPassword, u.tokenService.PasswordHashParams)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err, slog.Any(key.UserID, userData.ID))
		return le.ErrInternalServerError
	}

	updatedUser := entity.User{
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

func (u *Usecase) LogoutUser(ctx context.Context, data entity.UserDeviceRequestData, appID string) error {
	const method = "usecase.Usecase.LogoutUser"

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

	userID, err := u.tokenService.GetUserID(ctx, appID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	// Check if the device exists
	deviceID, err := u.sessionService.GetUserDeviceID(ctx, userID, data.UserAgent)
	if err != nil {
		if errors.Is(err, storage.ErrUserDeviceNotFound) {
			handleError(ctx, log, storage.ErrUserDeviceNotFound, err)
			return domain.ErrUserDeviceNotFound
		}

		handleError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		return err
	}

	log.Info("user logged out",
		slog.String(key.UserID, userID),
		slog.String(key.DeviceID, deviceID),
	)

	if err = u.sessionService.DeleteSession(ctx, userID, deviceID, appID); err != nil {
		handleError(ctx, log, domain.ErrFailedToDeleteSession, err)
		return domain.ErrFailedToDeleteSession
	}

	return nil
}

func (u *Usecase) RefreshTokens(ctx context.Context, data *entity.RefreshTokenRequestData) (entity.AuthTokenData, error) {
	const method = "usecase.Usecase.RefreshTokens"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return entity.AuthTokenData{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
		return entity.AuthTokenData{}, err
	}

	userSession, err := u.sessionService.CheckSessionAndDevice(ctx, data.RefreshToken, data.UserDevice)

	switch {
	case errors.Is(err, storage.ErrSessionNotFound):
		handleError(ctx, log, ErrSessionNotFound, err)
		return entity.AuthTokenData{}, ErrSessionNotFound
	case errors.Is(err, session.ErrSessionExpired):
		handleError(ctx, log, ErrSessionExpired, err)
		return entity.AuthTokenData{}, ErrSessionExpired
	case errors.Is(err, storage.ErrUserDeviceNotFound):
		handleError(ctx, log, storage.ErrUserDeviceNotFound, err)
		return entity.AuthTokenData{}, ErrUserDeviceNotFound
	case err != nil:
		handleError(ctx, log, ErrFailedToCheckSessionAndDevice, err)
		return entity.AuthTokenData{}, ErrInternalServerError
	}

	if err = u.sessionService.DeleteRefreshToken(ctx, data.RefreshToken); err != nil {
		handleError(ctx, log, ErrFailedToDeleteRefreshToken, err)
		return entity.AuthTokenData{}, ErrInternalServerError
	}

	user := entity.User{
		ID:    userSession.UserID,
		AppID: userSession.AppID,
	}

	tokenData, err := u.sessionService.CreateUserSession(ctx, user, data.UserDevice)
	if err != nil {
		handleError(ctx, log, ErrFailedToCreateUserSession, err, slog.Any(key.UserID, userSession.UserID))
		return entity.AuthTokenData{}, ErrInternalServerError
	}

	log.Info("tokens created", slog.Any(key.UserID, userSession.UserID))

	return tokenData, nil
}

func (u *Usecase) GetJWKS(ctx context.Context, data *entity.JWKSRequestData) (entity.JWKS, error) {
	const method = "usecase.Usecase.GetJWKS"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return entity.JWKS{}, err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.storage.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, le.ErrAppIDDoesNotExist) {
			handleError(ctx, log, le.ErrAppIDDoesNotExist, err, slog.Any(key.AppID, data.AppID))
			return entity.JWKS{}, le.ErrAppIDDoesNotExist
		}

		handleError(ctx, log, le.ErrFailedToValidateAppID, err, slog.Any(key.AppID, data.AppID))
		return entity.JWKS{}, err
	}

	// Read the public key from the PEM file
	publicKey, err := u.tokenService.GetPublicKey(data.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetJWKS, err)
		return entity.JWKS{}, err
	}

	kid, err := u.tokenService.GetKeyID(data.AppID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetJWKS, err)
		return entity.JWKS{}, err
	}

	jwk := entity.JWK{
		Alg: u.tokenService.SigningMethod,
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
		return entity.JWKS{}, le.ErrFailedToGetJWKS
	}

	// Construct a JWKS with the JWK
	jwksSlice := []entity.JWK{jwk}
	jwks := u.constructJWKS(jwksSlice...)

	log.Info("JWKS retrieved")

	return jwks, nil
}

func (u *Usecase) constructJWKS(jwks ...entity.JWK) entity.JWKS {
	return entity.JWKS{
		Keys: jwks,
		TTL:  u.tokenService.JWKSetTTL,
	}
}

//
//func (u *Usecase) GetUserByID(ctx context.Context, data *entity.UserRequestData) (entity.User, error) {
//	const method = "usecase.Usecase.GetUser"
//
//	reqID, err := u.getReqID(ctx, method)
//	if err != nil {
//		return entity.User{}, err
//	}
//
//	log := u.log.With(
//		slog.String(key.RequestID, reqID),
//		slog.String(key.Method, method),
//	)
//
//	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
//		return entity.User{}, err
//	}
//
//	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
//	if err != nil {
//		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
//		return entity.User{}, le.ErrFailedToGetUserIDFromToken
//	}
//
//	user, err := u.storage.GetUserByID(ctx, userID, data.AppID)
//	if err != nil {
//		if errors.Is(err, le.ErrUserNotFound) {
//			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
//			return entity.User{}, le.ErrUserNotFound
//		}
//
//		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
//		return entity.User{}, le.ErrFailedToGetUser
//	}
//
//	log.Info("user found by ID", slog.String(key.UserID, userID))
//
//	return user, nil
//}
//
//func (u *Usecase) UpdateUser(ctx context.Context, data *entity.UserRequestData) error {
//	const method = "usecase.Usecase.UpdateUser"
//
//	reqID, err := u.getReqID(ctx, method)
//	if err != nil {
//		return err
//	}
//
//	log := u.log.With(
//		slog.String(key.RequestID, reqID),
//		slog.String(key.Method, method),
//	)
//
//	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
//		return err
//	}
//
//	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
//	if err != nil {
//		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
//		return le.ErrFailedToGetUserIDFromToken
//	}
//
//	userDataFromDB, err := u.storage.GetUserData(ctx, userID, data.AppID)
//	if err != nil {
//		if errors.Is(err, le.ErrUserNotFound) {
//			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
//			return le.ErrUserNotFound
//		}
//
//		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
//		return le.ErrFailedToGetUser
//	}
//
//	if err = updateUserFields(ctx, u, data, userDataFromDB, log); err != nil {
//		return err
//	}
//
//	log.Info("user updated", slog.String(key.UserID, userID))
//
//	return nil
//}
//
//func updateUserFields(ctx context.Context, u *Usecase, data *entity.UserRequestData, userDataFromDB entity.User, log *slog.Logger) error {
//	updatedUser := entity.User{
//		ID:        userDataFromDB.ID,
//		Email:     data.Email,
//		AppID:     data.AppID,
//		UpdatedAt: time.Now(),
//	}
//
//	if err := u.handlePasswordUpdate(ctx, data, userDataFromDB, &updatedUser, log); err != nil {
//		return err
//	}
//
//	if err := u.handleEmailUpdate(ctx, userDataFromDB, &updatedUser, log); err != nil {
//		return err
//	}
//
//	err := u.storage.UpdateUser(ctx, updatedUser)
//	if err != nil {
//		handleError(ctx, log, le.ErrFailedToUpdateUser, err, slog.Any(key.UserID, userDataFromDB.ID))
//		return le.ErrInternalServerError
//	}
//
//	return nil
//}
//
//func (u *Usecase) handlePasswordUpdate(
//	ctx context.Context,
//	data *entity.UserRequestData,
//	userDataFromDB entity.User,
//	updatedUser *entity.User,
//	log *slog.Logger,
//) error {
//	if data.UpdatedPassword == "" {
//		return nil
//	}
//
//	if err := u.checkPasswordHashMatch(userDataFromDB.PasswordHash, data.Password); err != nil {
//		if errors.Is(err, le.ErrPasswordsDoNotMatch) {
//			handleError(ctx, log, le.ErrCurrentPasswordIsIncorrect, err, slog.Any(key.UserID, userDataFromDB.ID))
//			return le.ErrCurrentPasswordIsIncorrect
//		}
//
//		handleError(ctx, log, le.ErrFailedToCheckIfPasswordMatch, err, slog.Any(key.UserID, userDataFromDB.ID))
//		return le.ErrInternalServerError
//	}
//
//	if err := u.checkPasswordHashMatch(userDataFromDB.PasswordHash, data.UpdatedPassword); err == nil {
//		handleError(ctx, log, le.ErrNoPasswordChangesDetected, nil, slog.Any(key.UserID, userDataFromDB.ID))
//		return le.ErrNoPasswordChangesDetected
//	}
//
//	updatedPassHash, err := jwt.PasswordHash(data.UpdatedPassword, u.tokenService.PasswordHashParams)
//	if err != nil {
//		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err, slog.Any(key.UserID, userDataFromDB.ID))
//		return le.ErrInternalServerError
//	}
//
//	updatedUser.PasswordHash = updatedPassHash
//	return nil
//}

func (u *Usecase) checkPasswordHashMatch(hash, password string) error {
	matched, err := jwt.PasswordMatch(hash, password, u.tokenService.PasswordHashParams)
	if err != nil {
		return err
	}

	if !matched {
		return le.ErrPasswordsDoNotMatch
	}

	return nil
}

//func (u *Usecase) handleEmailUpdate(ctx context.Context, userDataFromDB entity.User, updatedUser *entity.User, log *slog.Logger) error {
//	if updatedUser.Email == "" {
//		return nil
//	}
//
//	if updatedUser.Email == userDataFromDB.Email {
//		handleError(ctx, log, le.ErrNoEmailChangesDetected, nil, slog.Any(key.UserID, userDataFromDB.ID))
//		return le.ErrNoEmailChangesDetected
//	}
//
//	userStatus, err := u.storage.GetUserStatusByEmail(ctx, updatedUser.Email)
//	if err != nil {
//		return err
//	}
//
//	if userStatus == entity.UserStatusActive.String() {
//		return le.ErrEmailAlreadyTaken
//	}
//
//	return nil
//}
//
//func (u *Usecase) DeleteUser(ctx context.Context, data *entity.UserRequestData) error {
//	const method = "usecase.Usecase.DeleteUser"
//
//	reqID, err := u.getReqID(ctx, method)
//	if err != nil {
//		return err
//	}
//
//	log := u.log.With(
//		slog.String(key.RequestID, reqID),
//		slog.String(key.Method, method),
//	)
//
//	if err = u.validateAppID(ctx, log, data.AppID); err != nil {
//		return err
//	}
//
//	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
//	if err != nil {
//		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
//		return le.ErrFailedToGetUserIDFromToken
//	}
//
//	user := entity.User{
//		ID:        userID,
//		AppID:     data.AppID,
//		DeletedAt: time.Now(),
//	}
//
//	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
//		userStatus, err := u.storage.GetUserStatusByID(ctx, user.ID)
//		if err != nil {
//			return err
//		}
//
//		switch userStatus {
//		case entity.UserStatusActive.String():
//			if err := u.cleanupUserData(ctx, log, user); err != nil {
//				return err
//			}
//			return nil
//		case entity.UserStatusSoftDeleted.String(), entity.UserStatusNotFound.String():
//			return le.ErrUserNotFound
//		default:
//			return fmt.Errorf("%s: unknown user status: %s", method, userStatus)
//		}
//	}); err != nil {
//		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
//		return err
//	}
//
//	log.Info("user soft-deleted", slog.String(key.UserID, user.ID))
//
//	return nil
//}
//
//func (u *Usecase) cleanupUserData(ctx context.Context, log *slog.Logger, user entity.User) error {
//	if err := u.storage.DeleteUser(ctx, user); err != nil {
//		handleError(ctx, log, le.ErrFailedToDeleteUser, err, slog.Any(key.UserID, user.ID))
//		return le.ErrFailedToDeleteUser
//	}
//
//	if err := u.sessionService.DeleteAllUserSessions(ctx, user); err != nil {
//		handleError(ctx, log, ErrFailedToDeleteAllUserSessions, err, slog.Any(key.UserID, user.ID))
//		return ErrFailedToDeleteAllUserSessions
//	}
//
//	if err := u.storage.DeleteAllTokens(ctx, user.ID, user.AppID); err != nil {
//		handleError(ctx, log, le.ErrFailedToDeleteTokens, err, slog.Any(key.UserID, user.ID))
//		return le.ErrFailedToDeleteTokens
//	}
//
//	return nil
//}

// getReqID returns request ID from context
func (u *Usecase) getReqID(ctx context.Context, method string) (string, error) {
	reqID, err := requestid.FromContext(ctx)
	if err != nil {
		handleError(ctx, u.log, le.ErrFailedToGetRequestIDFromCtx, err, slog.Any(key.Method, method))
		return "", err
	}
	return reqID, nil
}
