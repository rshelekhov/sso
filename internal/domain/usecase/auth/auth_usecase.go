package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/e"
)

type Auth struct {
	log             *slog.Logger
	txMgr           TransactionManager
	sessionMgr      SessionManager
	userMgr         UserdataManager
	mailService     MailService
	tokenMgr        TokenManager
	verificationMgr VerificationManager
	storage         Storage
}

type (
	SessionManager interface {
		CreateSession(ctx context.Context, reqData entity.SessionRequestData) (entity.SessionTokens, error)
		GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error)
		GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
		DeleteSession(ctx context.Context, sessionReqData entity.SessionRequestData) error
		DeleteRefreshToken(ctx context.Context, refreshToken string) error
	}

	UserdataManager interface {
		GetUserByEmail(ctx context.Context, email string) (entity.User, error)
		GetUserStatusByEmail(ctx context.Context, email string) (string, error)
		GetUserData(ctx context.Context, userID string) (entity.User, error)
		UpdateUserData(ctx context.Context, user entity.User) error
	}

	MailService interface {
		SendEmail(ctx context.Context, data mail.Data) error
	}

	TokenManager interface {
		HashPassword(password string) (string, error)
		PasswordMatch(hash, password string) (bool, error)
		ExtractUserIDFromTokenInContext(ctx context.Context, clientID string) (string, error)
		PublicKey(clientID string) (any, error)
		Kid(clientID string) (string, error)
		JWKSTTL() time.Duration
		SigningMethod() string
	}

	VerificationManager interface {
		CreateToken(ctx context.Context, user entity.User, verificationEndpoint string, tokenType entity.VerificationTokenType) (entity.VerificationToken, error)
		GetTokenData(ctx context.Context, token string) (entity.VerificationToken, error)
		DeleteToken(ctx context.Context, token string) error
	}

	TransactionManager interface {
		WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	}

	Storage interface {
		ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error
		RegisterUser(ctx context.Context, user entity.User) error
		MarkEmailVerified(ctx context.Context, userID string) error
	}
)

func NewUsecase(
	log *slog.Logger,
	ss SessionManager,
	us UserdataManager,
	ms MailService,
	ts TokenManager,
	vs VerificationManager,
	tm TransactionManager,
	storage Storage,
) *Auth {
	return &Auth{
		log:             log,
		sessionMgr:      ss,
		userMgr:         us,
		mailService:     ms,
		tokenMgr:        ts,
		verificationMgr: vs,
		txMgr:           tm,
		storage:         storage,
	}
}

// Login checks if user with given credentials exists in the system
func (u *Auth) Login(ctx context.Context, clientID string, reqData *entity.UserRequestData) (entity.SessionTokens, error) {
	const method = "usecase.Auth.Login"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	userData, err := u.userMgr.GetUserByEmail(ctx, reqData.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err)
			return entity.SessionTokens{}, domain.ErrUserNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetUserByEmail, err)
		return entity.SessionTokens{}, domain.ErrFailedToGetUserByEmail
	}

	if err = u.verifyPassword(ctx, userData, reqData.Password); err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			e.LogError(ctx, log, domain.ErrInvalidCredentials, err, slog.Any("userID", userData.ID))
			return entity.SessionTokens{}, domain.ErrInvalidCredentials
		}

		e.LogError(ctx, log, domain.ErrFailedToVerifyPassword, err, slog.Any("userID", userData.ID))
		return entity.SessionTokens{}, domain.ErrFailedToVerifyPassword
	}

	sessionReqData := entity.SessionRequestData{
		UserID:   userData.ID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserDevice.UserAgent,
			IP:        reqData.UserDevice.IP,
		},
	}

	tokenData := entity.SessionTokens{}

	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		tokenData, err = u.sessionMgr.CreateSession(txCtx, sessionReqData)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		return nil
	}); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.Any("userID", userData.ID))
		return entity.SessionTokens{}, err
	}

	log.Info("user authenticated, tokens created",
		slog.String("userID", userData.ID),
	)

	return tokenData, nil
}

// RegisterUser creates new user in the system and returns jwtoken
func (u *Auth) RegisterUser(ctx context.Context, clientID string, reqData *entity.UserRequestData, verifyEmailEndpoint string) (entity.SessionTokens, error) {
	const method = "usecase.Auth.RegisterUser"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	hash, err := u.tokenMgr.HashPassword(reqData.Password)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToGeneratePasswordHash, err)
		return entity.SessionTokens{}, domain.ErrFailedToGeneratePasswordHash
	}

	newUser := entity.NewUser(reqData.Email, hash)

	authTokenData := entity.SessionTokens{}

	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		userStatus, err := u.userMgr.GetUserStatusByEmail(txCtx, newUser.Email)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserStatusByEmail, err)
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			return domain.ErrUserAlreadyExists
		case entity.UserStatusSoftDeleted.String():
			if err = u.storage.ReplaceSoftDeletedUser(txCtx, newUser); err != nil {
				return fmt.Errorf("%w: %w", domain.ErrFailedToReplaceSoftDeletedUser, err)
			}
		case entity.UserStatusNotFound.String():
			if err = u.storage.RegisterUser(txCtx, newUser); err != nil {
				return fmt.Errorf("%w: %w", domain.ErrFailedToRegisterUser, err)
			}
		default:
			return fmt.Errorf("%w: %s", domain.ErrUnknownUserStatus, userStatus)
		}

		sessionReqData := entity.SessionRequestData{
			UserID:   newUser.ID,
			ClientID: clientID,
			UserDevice: entity.UserDeviceRequestData{
				UserAgent: reqData.UserDevice.UserAgent,
				IP:        reqData.UserDevice.IP,
			},
		}

		authTokenData, err = u.sessionMgr.CreateSession(txCtx, sessionReqData)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		tokenData, err := u.verificationMgr.CreateToken(txCtx, newUser, verifyEmailEndpoint, entity.TokenTypeVerifyEmail)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateVerificationToken, err)
		}

		if err = u.sendEmailWithToken(txCtx, tokenData, entity.EmailTemplateTypeVerifyEmail); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToSendVerificationEmail, err)
		}

		return nil
	}); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.Any("userID", newUser.ID))
		return entity.SessionTokens{}, err
	}

	log.Info("user and tokens created, verification email sent",
		slog.String("userID", newUser.ID),
	)

	return authTokenData, nil
}

func (u *Auth) VerifyEmail(ctx context.Context, verificationToken string) (entity.VerificationResult, error) {
	const method = "usecase.Auth.VerifyEmail"

	log := u.log.With(
		slog.String("method", method),
	)

	result := entity.VerificationResult{}

	if err := u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		tokenData, err := u.handleTokenProcessing(txCtx, verificationToken, entity.EmailTemplateTypeVerifyEmail)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token != verificationToken {
			result.TokenExpired = true
			log.Info("token expired, a new email with a new token has been sent to the user", slog.Any("userID", tokenData.UserID))
			return nil
		}

		if err = u.storage.MarkEmailVerified(txCtx, tokenData.UserID); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToMarkEmailVerified, err)
		}

		log.Info("email verified", slog.String("userID", tokenData.UserID))
		return nil
	}); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.Any("verificationToken", verificationToken))
		return entity.VerificationResult{}, err
	}

	return result, nil
}

func (u *Auth) ResetPassword(ctx context.Context, clientID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error {
	const method = "usecase.Auth.ResetPassword"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	userData, err := u.userMgr.GetUserByEmail(ctx, reqData.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err, slog.Any("email", reqData.Email))
			return domain.ErrUserNotFound
		}

		e.LogError(ctx, u.log, domain.ErrFailedToGetUserByEmail, err, slog.Any("email", reqData.Email))
		return domain.ErrFailedToGetUserByEmail
	}

	tokenData, err := u.verificationMgr.CreateToken(ctx, userData, changePasswordEndpoint, entity.TokenTypeResetPassword)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCreateVerificationToken, err)
		return domain.ErrFailedToCreateVerificationToken
	}

	if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeResetPassword); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToSendResetPasswordEmail, err)
		return domain.ErrFailedToSendResetPasswordEmail
	}

	log.Info("reset password email sent",
		slog.String("userID", userData.ID),
		slog.String("email", reqData.Email),
	)

	return nil
}

func (u *Auth) ChangePassword(ctx context.Context, clientID string, reqData *entity.ChangePasswordRequestData) (entity.ChangingPasswordResult, error) {
	const method = "usecase.Auth.ChangePassword"

	log := u.log.With(
		slog.String("method", method),
	)

	result := entity.ChangingPasswordResult{}

	if err := u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		tokenData, err := u.handleTokenProcessing(txCtx, reqData.ResetPasswordToken, entity.EmailTemplateTypeResetPassword)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token != reqData.ResetPasswordToken {
			result.TokenExpired = true
			log.Info("token expired, a new email with a new token has been sent to the user", slog.Any("userID", tokenData.UserID))
			return nil
		}

		userDataFromDB, err := u.userMgr.GetUserData(txCtx, tokenData.UserID)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
		}

		if err = u.checkPasswordHashAndUpdate(txCtx, userDataFromDB, reqData); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCheckPasswordHashAndUpdate, err)
		}

		log.Info("password changed", slog.String("userID", userDataFromDB.ID))

		return nil
	}); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.Any("token", reqData.ResetPasswordToken))
		return entity.ChangingPasswordResult{}, err
	}

	return result, nil
}

func (u *Auth) LogoutUser(ctx context.Context, clientID string, reqData *entity.UserDeviceRequestData) error {
	const method = "usecase.Auth.LogoutUser"

	log := u.log.With(
		slog.String("method", method),
	)

	userID, err := u.tokenMgr.ExtractUserIDFromTokenInContext(ctx, clientID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	sessionReqData := entity.SessionRequestData{
		UserID:   userID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserAgent,
			IP:        reqData.IP,
		},
	}

	// Check if the device exists
	sessionReqData.DeviceID, err = u.sessionMgr.GetUserDeviceID(ctx, userID, reqData.UserAgent)
	if err != nil {
		if errors.Is(err, domain.ErrUserDeviceNotFound) {
			e.LogError(ctx, log, domain.ErrUserDeviceNotFound, err)
			return domain.ErrUserDeviceNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		return domain.ErrFailedToGetDeviceID
	}

	if err = u.sessionMgr.DeleteSession(ctx, sessionReqData); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToDeleteSession, err)
		return domain.ErrFailedToDeleteSession
	}

	log.Info("user logged out",
		slog.String("userID", sessionReqData.UserID),
		slog.String("deviceID", sessionReqData.DeviceID),
	)

	return nil
}

func (u *Auth) RefreshTokens(ctx context.Context, clientID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error) {
	const method = "usecase.Auth.RefreshTokens"

	log := u.log.With(
		slog.String("method", method),
	)

	userSession, err := u.sessionMgr.GetSessionByRefreshToken(ctx, reqData.RefreshToken)

	switch {
	case errors.Is(err, domain.ErrSessionNotFound):
		e.LogError(ctx, log, domain.ErrSessionNotFound, err)
		return entity.SessionTokens{}, domain.ErrSessionNotFound
	case errors.Is(err, domain.ErrSessionExpired):
		e.LogError(ctx, log, domain.ErrSessionExpired, err)
		return entity.SessionTokens{}, domain.ErrSessionExpired
	case err != nil:
		e.LogError(ctx, log, domain.ErrFailedToGetSessionByRefreshToken, err)
		return entity.SessionTokens{}, domain.ErrFailedToGetSessionByRefreshToken
	}

	_, err = u.sessionMgr.GetUserDeviceID(ctx, userSession.UserID, reqData.UserDevice.UserAgent)
	if err != nil {
		if errors.Is(err, domain.ErrUserDeviceNotFound) {
			e.LogError(ctx, log, domain.ErrUserDeviceNotFound, err)
			return entity.SessionTokens{}, domain.ErrUserDeviceNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		return entity.SessionTokens{}, domain.ErrFailedToGetDeviceID
	}

	if err = u.sessionMgr.DeleteRefreshToken(ctx, reqData.RefreshToken); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToDeleteRefreshToken, err)
		return entity.SessionTokens{}, domain.ErrFailedToDeleteRefreshToken
	}

	sessionReqData := entity.SessionRequestData{
		UserID:   userSession.UserID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserDevice.UserAgent,
			IP:        reqData.UserDevice.IP,
		},
	}

	tokenData, err := u.sessionMgr.CreateSession(ctx, sessionReqData)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any("userID", userSession.UserID))
		return entity.SessionTokens{}, domain.ErrFailedToCreateUserSession
	}

	log.Info("tokens created", slog.Any("userID", userSession.UserID))

	return tokenData, nil
}

func (u *Auth) GetJWKS(ctx context.Context, clientID string) (entity.JWKS, error) {
	const method = "usecase.Auth.GetJWKS"

	log := u.log.With(
		slog.String("method", method),
	)

	publicKey, err := u.tokenMgr.PublicKey(clientID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToGetPublicKey, err)
		return entity.JWKS{}, domain.ErrFailedToGetPublicKey
	}

	kid, err := u.tokenMgr.Kid(clientID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToGetKeyID, err)
		return entity.JWKS{}, domain.ErrFailedToGetKeyID
	}

	jwk := entity.JWK{
		Alg: u.tokenMgr.SigningMethod(),
		Use: "alg",
		Kid: kid,
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		p := pub.Params()
		jwk.Kty = "EC"
		jwk.Crv = p.Name
		jwk.X = base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	default:
		return entity.JWKS{}, domain.ErrFailedToGetJWKS
	}

	// Construct a JWKS with the JWK
	jwksSlice := []entity.JWK{jwk}
	jwks := u.constructJWKS(jwksSlice...)

	log.Info("JWKS retrieved")

	return jwks, nil
}

// verifyPassword checks if password is correct
func (u *Auth) verifyPassword(ctx context.Context, userData entity.User, password string) error {
	const method = "usecase.Auth.verifyPassword"

	userData, err := u.userMgr.GetUserData(ctx, userData.ID)
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
	}

	matched, err := u.tokenMgr.PasswordMatch(userData.PasswordHash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if !matched {
		return domain.ErrInvalidCredentials
	}

	return nil
}

func (u *Auth) sendEmailWithToken(ctx context.Context, tokenData entity.VerificationToken, templateType entity.EmailTemplateType) error {
	emailData := mail.Data{
		TemplateType: templateType,
		Subject:      templateType.Subject(),
		Recipient:    tokenData.Email,
		Data: map[string]string{
			"Recipient": tokenData.Email,
			"URL":       fmt.Sprintf("%s%s", tokenData.Endpoint, tokenData.Token),
		},
	}

	return u.mailService.SendEmail(ctx, emailData)
}

func (u *Auth) handleTokenProcessing(
	ctx context.Context,
	token string,
	emailTemplateType entity.EmailTemplateType,
) (entity.VerificationToken, error) {
	tokenData, err := u.verificationMgr.GetTokenData(ctx, token)
	if err != nil {
		return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToGetVerificationTokenData, err)
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		u.log.Info("token expired",
			slog.Any("userID", tokenData.UserID),
			slog.Any("token", tokenData.Token))

		if err = u.verificationMgr.DeleteToken(ctx, tokenData.Token); err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToDeleteVerificationToken, err)
		}

		userData := entity.User{
			ID:    tokenData.UserID,
			Email: tokenData.Email,
		}

		tokenData, err = u.verificationMgr.CreateToken(ctx, userData, tokenData.Endpoint, tokenData.Type)
		if err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToCreateVerificationToken, err)
		}

		if err = u.sendEmailWithToken(ctx, tokenData, emailTemplateType); err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToSendEmail, err)
		}

		return tokenData, nil
	}

	return tokenData, nil
}

func (u *Auth) checkPasswordHashAndUpdate(
	ctx context.Context,
	userData entity.User,
	reqData *entity.ChangePasswordRequestData,
) error {
	const method = "usecase.Auth.checkPasswordHashAndUpdate"

	err := u.validatePasswordChanged(userData.PasswordHash, reqData.UpdatedPassword)
	if err != nil {
		return err
	}

	updatedPassHash, err := u.tokenMgr.HashPassword(reqData.UpdatedPassword)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGeneratePasswordHash, err)
	}

	updatedUser := entity.User{
		ID:           userData.ID,
		PasswordHash: updatedPassHash,
		UpdatedAt:    time.Now(),
	}

	if err = u.userMgr.UpdateUserData(ctx, updatedUser); err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToUpdateUser, err)
	}

	return nil
}

func (u *Auth) validatePasswordChanged(hash, password string) error {
	const method = "usecase.Auth.validatePasswordChanged"

	matched, err := u.tokenMgr.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if matched {
		return domain.ErrNoPasswordChangesDetected
	}

	return nil
}

func (u *Auth) constructJWKS(jwks ...entity.JWK) entity.JWKS {
	return entity.JWKS{
		Keys: jwks,
		TTL:  u.tokenMgr.JWKSTTL(),
	}
}
