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

	"github.com/rshelekhov/golib/observability/tracing"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/e"
	"go.opentelemetry.io/otel/attribute"
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
	metrics         MetricsRecorder
	tokenMetrics    TokenMetricsRecorder
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
	metrics MetricsRecorder,
	tokenMetrics TokenMetricsRecorder,
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
		metrics:         metrics,
		tokenMetrics:    tokenMetrics,
	}
}

// Login checks if user with given credentials exists in the system
func (u *Auth) Login(ctx context.Context, clientID string, reqData *entity.UserRequestData) (userID string, tokens entity.SessionTokens, err error) {
	const method = "usecase.Auth.Login"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
		tracing.String("user.email", reqData.Email),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
		slog.String("user.email", reqData.Email),
	)

	u.metrics.RecordLoginAttempt(ctx, clientID)

	ctx, getUserByEmailSpan := tracing.StartSpan(ctx, "get_user_by_email")

	userData, err := u.userMgr.GetUserByEmail(ctx, reqData.Email)
	if err != nil {
		tracing.RecordError(getUserByEmailSpan, err)
		getUserByEmailSpan.End()

		if errors.Is(err, domain.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err)
			u.metrics.RecordLoginError(ctx, clientID, attribute.String("error.type", domain.ErrUserNotFound.Error()))
			return "", entity.SessionTokens{}, domain.ErrUserNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetUserByEmail, err)
		u.metrics.RecordLoginError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetUserByEmail.Error()))
		return "", entity.SessionTokens{}, domain.ErrFailedToGetUserByEmail
	}

	getUserByEmailSpan.End()

	ctx, verifyPasswordSpan := tracing.StartSpan(ctx, "verify_password")
	if err = u.verifyPassword(ctx, userData, reqData.Password); err != nil {
		tracing.RecordError(verifyPasswordSpan, err)
		verifyPasswordSpan.End()

		if errors.Is(err, domain.ErrInvalidCredentials) {
			e.LogError(ctx, log, domain.ErrInvalidCredentials, err, slog.String("user.id", userData.ID))
			u.metrics.RecordLoginError(ctx, clientID, attribute.String("error.type", domain.ErrInvalidCredentials.Error()))
			return "", entity.SessionTokens{}, domain.ErrInvalidCredentials
		}

		e.LogError(ctx, log, domain.ErrFailedToVerifyPassword, err, slog.String("user.id", userData.ID))
		u.metrics.RecordLoginError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToVerifyPassword.Error()))

		return "", entity.SessionTokens{}, domain.ErrFailedToVerifyPassword
	}

	verifyPasswordSpan.End()

	sessionReqData := entity.SessionRequestData{
		UserID:   userData.ID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserDevice.UserAgent,
			IP:        reqData.UserDevice.IP,
		},
	}

	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		txCtx, transactionSpan := tracing.StartSpan(txCtx, "transaction")
		tracing.EndSpanOnError(transactionSpan, &err)

		transactionSpan.AddEvent("Creating session")
		tokens, err = u.sessionMgr.CreateSession(txCtx, sessionReqData)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		return nil
	}); err != nil {
		tracing.RecordError(span, err)
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.String("user.id", userData.ID))
		u.metrics.RecordLoginError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToCommitTransaction.Error()))
		return "", entity.SessionTokens{}, err
	}

	log.Info("user authenticated, tokens created",
		slog.String("user.id", userData.ID),
	)

	u.metrics.RecordLoginSuccess(ctx, clientID)

	return userData.ID, tokens, nil
}

// RegisterUser creates new user in the system and returns jwtoken
func (u *Auth) RegisterUser(
	ctx context.Context,
	clientID string,
	reqData *entity.UserRequestData,
	verifyEmailEndpoint string,
) (
	userID string,
	tokens entity.SessionTokens,
	err error,
) {
	const method = "usecase.Auth.RegisterUser"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
		tracing.String("user.email", reqData.Email),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
		slog.String("user.email", reqData.Email),
	)

	u.metrics.RecordRegistrationAttempt(ctx, clientID)

	hash, err := u.tokenMgr.HashPassword(reqData.Password)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToGeneratePasswordHash, err)
		u.metrics.RecordRegistrationError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGeneratePasswordHash.Error()))
		return "", entity.SessionTokens{}, domain.ErrFailedToGeneratePasswordHash
	}

	newUser := entity.NewUser(reqData.Email, hash)

	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		txCtx, transactionSpan := tracing.StartSpan(txCtx, "transaction")
		tracing.EndSpanOnError(transactionSpan, &err)

		userStatus, err := u.userMgr.GetUserStatusByEmail(txCtx, newUser.Email)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserStatusByEmail, err)
		}

		if err := u.handleUserStatus(txCtx, userStatus, newUser); err != nil {
			return err
		}

		sessionReq := entity.SessionRequestData{
			UserID:   newUser.ID,
			ClientID: clientID,
			UserDevice: entity.UserDeviceRequestData{
				UserAgent: reqData.UserDevice.UserAgent,
				IP:        reqData.UserDevice.IP,
			},
		}

		transactionSpan.AddEvent("Creating session")
		tokens, err = u.sessionMgr.CreateSession(txCtx, sessionReq)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		transactionSpan.AddEvent("Creating and sending verification email with token")
		if err := u.createAndSendVerificationToken(txCtx, newUser, verifyEmailEndpoint); err != nil {
			return err
		}

		return nil
	}); err != nil {
		tracing.RecordError(span, err)
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.String("user.id", newUser.ID))
		u.metrics.RecordRegistrationError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToCommitTransaction.Error()))
		return "", entity.SessionTokens{}, err
	}

	log.Info("user and tokens created, verification email sent",
		slog.String("user.id", newUser.ID),
	)

	u.metrics.RecordRegistrationSuccess(ctx, clientID)

	return newUser.ID, tokens, nil
}

func (u *Auth) handleUserStatus(ctx context.Context, status string, user entity.User) error {
	switch status {
	case entity.UserStatusActive.String():
		return domain.ErrUserAlreadyExists
	case entity.UserStatusSoftDeleted.String():
		if err := u.storage.ReplaceSoftDeletedUser(ctx, user); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToReplaceSoftDeletedUser, err)
		}
	case entity.UserStatusNotFound.String():
		if err := u.storage.RegisterUser(ctx, user); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToRegisterUser, err)
		}
	default:
		return fmt.Errorf("%w: %s", domain.ErrUnknownUserStatus, status)
	}
	return nil
}

func (u *Auth) createAndSendVerificationToken(ctx context.Context, user entity.User, endpoint string) error {
	tokenData, err := u.verificationMgr.CreateToken(ctx, user, endpoint, entity.TokenTypeVerifyEmail)
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToCreateVerificationToken, err)
	}

	if err := u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeVerifyEmail); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToSendVerificationEmail, err)
	}

	return nil
}

func (u *Auth) VerifyEmail(ctx context.Context, verificationToken string) (entity.VerificationResult, error) {
	const method = "usecase.Auth.VerifyEmail"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	log := u.log.With(
		slog.String("method", method),
	)

	u.metrics.RecordEmailVerificationAttempt(ctx)

	result := entity.VerificationResult{}

	var err error
	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		txCtx, transactionSpan := tracing.StartSpan(txCtx, "transaction")
		tracing.EndSpanOnError(transactionSpan, &err)

		tokenData, err := u.handleTokenProcessing(txCtx, verificationToken, entity.EmailTemplateTypeVerifyEmail)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token != verificationToken {
			result.TokenExpired = true
			transactionSpan.AddEvent("Token expired, a new email with a new token has been sent to the user")

			log.Info("token expired, a new email with a new token has been sent to the user", slog.String("user.id", tokenData.UserID))
			return nil
		}

		if err = u.storage.MarkEmailVerified(txCtx, tokenData.UserID); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToMarkEmailVerified, err)
		}

		log.Info("email verified", slog.String("user.id", tokenData.UserID))
		return nil
	}); err != nil {
		tracing.RecordError(span, err)
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.String("verificationToken", verificationToken))
		u.metrics.RecordEmailVerificationError(ctx, attribute.String("error.type", domain.ErrFailedToCommitTransaction.Error()))
		return entity.VerificationResult{}, err
	}

	u.metrics.RecordEmailVerificationSuccess(ctx)

	return result, nil
}

func (u *Auth) ResetPassword(ctx context.Context, clientID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error {
	const method = "usecase.Auth.ResetPassword"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
		tracing.String("user.email", reqData.Email),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
		slog.String("user.email", reqData.Email),
	)

	u.metrics.RecordPasswordResetAttempt(ctx, clientID)

	ctx, getUserByEmailSpan := tracing.StartSpan(ctx, "get_user_by_email")

	userData, err := u.userMgr.GetUserByEmail(ctx, reqData.Email)
	if err != nil {
		tracing.RecordError(getUserByEmailSpan, err)
		getUserByEmailSpan.End()

		if errors.Is(err, storage.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err, slog.String("email", reqData.Email))
			u.metrics.RecordPasswordResetError(ctx, clientID, attribute.String("error.type", domain.ErrUserNotFound.Error()))
			return domain.ErrUserNotFound
		}

		e.LogError(ctx, u.log, domain.ErrFailedToGetUserByEmail, err, slog.String("email", reqData.Email))
		u.metrics.RecordPasswordResetError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetUserByEmail.Error()))
		return domain.ErrFailedToGetUserByEmail
	}

	getUserByEmailSpan.End()

	ctx, createVerificationTokenSpan := tracing.StartSpan(ctx, "create_verification_token")
	tokenData, err := u.verificationMgr.CreateToken(ctx, userData, changePasswordEndpoint, entity.TokenTypeResetPassword)
	if err != nil {
		tracing.RecordError(createVerificationTokenSpan, err)
		createVerificationTokenSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToCreateVerificationToken, err)
		u.metrics.RecordPasswordResetError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToCreateVerificationToken.Error()))
		return domain.ErrFailedToCreateVerificationToken
	}

	createVerificationTokenSpan.End()

	span.AddEvent("Sending reset password email with token")
	if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeResetPassword); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToSendResetPasswordEmail, err)
		u.metrics.RecordPasswordResetError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToSendResetPasswordEmail.Error()))
		return domain.ErrFailedToSendResetPasswordEmail
	}

	log.Info("reset password email sent",
		slog.String("user.id", userData.ID),
		slog.String("user.email", reqData.Email),
	)

	u.metrics.RecordPasswordResetSuccess(ctx, clientID)

	return nil
}

func (u *Auth) ChangePassword(ctx context.Context, clientID string, reqData *entity.ChangePasswordRequestData) (entity.ChangingPasswordResult, error) {
	const method = "usecase.Auth.ChangePassword"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
	)

	log := u.log.With(
		slog.String("method", method),
	)

	u.metrics.RecordChangePasswordAttempt(ctx, clientID)

	result := entity.ChangingPasswordResult{}

	var err error
	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		txCtx, transactionSpan := tracing.StartSpan(txCtx, method+".transaction")
		tracing.EndSpanOnError(transactionSpan, &err)

		tokenData, err := u.handleTokenProcessing(txCtx, reqData.ResetPasswordToken, entity.EmailTemplateTypeResetPassword)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token != reqData.ResetPasswordToken {
			result.TokenExpired = true
			transactionSpan.AddEvent("Token expired, a new email with a new token has been sent to the user")

			log.Info("token expired, a new email with a new token has been sent to the user", slog.String("user.id", tokenData.UserID))
			return nil
		}

		transactionSpan.AddEvent("Getting user data")
		userDataFromDB, err := u.userMgr.GetUserData(txCtx, tokenData.UserID)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
		}

		if err = u.checkPasswordHashAndUpdate(txCtx, userDataFromDB, reqData); err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCheckPasswordHashAndUpdate, err)
		}

		log.Info("password changed", slog.String("user.id", userDataFromDB.ID))

		return nil
	}); err != nil {
		tracing.RecordError(span, err)
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.String("token", reqData.ResetPasswordToken))
		u.metrics.RecordChangePasswordError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToCommitTransaction.Error()))
		return entity.ChangingPasswordResult{}, err
	}

	u.metrics.RecordChangePasswordSuccess(ctx, clientID)

	return result, nil
}

func (u *Auth) LogoutUser(ctx context.Context, clientID string, reqData *entity.UserDeviceRequestData) error {
	const method = "usecase.Auth.LogoutUser"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
		tracing.String("user.device.user_agent", reqData.UserAgent),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
		slog.String("user.device.user_agent", reqData.UserAgent),
	)

	u.metrics.RecordLogoutAttempt(ctx, clientID)

	ctx, extractUserIDSpan := tracing.StartSpan(ctx, "extract_user_id_from_token")

	userID, err := u.tokenMgr.ExtractUserIDFromTokenInContext(ctx, clientID)
	if err != nil {
		tracing.RecordError(extractUserIDSpan, err)
		extractUserIDSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		u.metrics.RecordLogoutError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToExtractUserIDFromContext.Error()))
		return domain.ErrFailedToExtractUserIDFromContext
	}

	extractUserIDSpan.End()

	sessionReqData := entity.SessionRequestData{
		UserID:   userID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserAgent,
			IP:        reqData.IP,
		},
	}

	// Check if the device exists
	ctx, getUserDeviceIDSpan := tracing.StartSpan(ctx, "get_user_device_id")
	sessionReqData.DeviceID, err = u.sessionMgr.GetUserDeviceID(ctx, userID, reqData.UserAgent)
	if err != nil {
		tracing.RecordError(getUserDeviceIDSpan, err)
		getUserDeviceIDSpan.End()

		if errors.Is(err, domain.ErrUserDeviceNotFound) {
			e.LogError(ctx, log, domain.ErrUserDeviceNotFound, err)
			u.metrics.RecordLogoutError(ctx, clientID, attribute.String("error.type", domain.ErrUserDeviceNotFound.Error()))
			return domain.ErrUserDeviceNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		u.metrics.RecordLogoutError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetDeviceID.Error()))
		return domain.ErrFailedToGetDeviceID
	}

	getUserDeviceIDSpan.End()

	ctx, deleteSessionSpan := tracing.StartSpan(ctx, "delete_session")
	if err = u.sessionMgr.DeleteSession(ctx, sessionReqData); err != nil {
		tracing.RecordError(deleteSessionSpan, err)
		deleteSessionSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToDeleteSession, err)
		u.metrics.RecordLogoutError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToDeleteSession.Error()))
		return domain.ErrFailedToDeleteSession
	}

	deleteSessionSpan.End()

	log.Info("user logged out",
		slog.String("user.id", sessionReqData.UserID),
		slog.String("user.device.id", sessionReqData.DeviceID),
	)

	u.tokenMetrics.RecordTokenRevokedLogout(ctx, clientID)
	u.metrics.RecordLogoutSuccess(ctx, clientID)

	return nil
}

func (u *Auth) RefreshTokens(ctx context.Context, clientID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error) {
	const method = "usecase.Auth.RefreshTokens"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
		tracing.String("user.device.user_agent", reqData.UserDevice.UserAgent),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
		slog.String("user.device.user_agent", reqData.UserDevice.UserAgent),
	)

	u.metrics.RecordRefreshTokensAttempt(ctx, clientID)

	ctx, getSessionByRefreshTokenSpan := tracing.StartSpan(ctx, "get_session_by_refresh_token")

	userSession, err := u.sessionMgr.GetSessionByRefreshToken(ctx, reqData.RefreshToken)

	switch {
	case errors.Is(err, domain.ErrSessionNotFound):
		tracing.RecordError(getSessionByRefreshTokenSpan, err)
		getSessionByRefreshTokenSpan.End()

		e.LogError(ctx, log, domain.ErrSessionNotFound, err)
		u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrSessionNotFound.Error()))
		return entity.SessionTokens{}, domain.ErrSessionNotFound
	case errors.Is(err, domain.ErrSessionExpired):
		tracing.RecordError(getSessionByRefreshTokenSpan, err)
		getSessionByRefreshTokenSpan.End()

		e.LogError(ctx, log, domain.ErrSessionExpired, err)
		u.metrics.RecordSessionExpired(ctx, clientID)
		return entity.SessionTokens{}, domain.ErrSessionExpired
	case err != nil:
		tracing.RecordError(getSessionByRefreshTokenSpan, err)
		getSessionByRefreshTokenSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToGetSessionByRefreshToken, err)
		u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetSessionByRefreshToken.Error()))
		return entity.SessionTokens{}, domain.ErrFailedToGetSessionByRefreshToken
	}

	getSessionByRefreshTokenSpan.End()

	ctx, getUserDeviceIDSpan := tracing.StartSpan(ctx, "get_user_device_id")
	_, err = u.sessionMgr.GetUserDeviceID(ctx, userSession.UserID, reqData.UserDevice.UserAgent)
	if err != nil {
		tracing.RecordError(getUserDeviceIDSpan, err)
		getUserDeviceIDSpan.End()

		if errors.Is(err, domain.ErrUserDeviceNotFound) {
			e.LogError(ctx, log, domain.ErrUserDeviceNotFound, err)
			u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrUserDeviceNotFound.Error()))
			return entity.SessionTokens{}, domain.ErrUserDeviceNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetDeviceID.Error()))
		return entity.SessionTokens{}, domain.ErrFailedToGetDeviceID
	}

	getUserDeviceIDSpan.End()

	ctx, deleteRefreshTokenSpan := tracing.StartSpan(ctx, "delete_refresh_token")
	if err = u.sessionMgr.DeleteRefreshToken(ctx, reqData.RefreshToken); err != nil {
		tracing.RecordError(deleteRefreshTokenSpan, err)
		deleteRefreshTokenSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToDeleteRefreshToken, err)
		u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToDeleteRefreshToken.Error()))
		return entity.SessionTokens{}, domain.ErrFailedToDeleteRefreshToken
	}

	deleteRefreshTokenSpan.End()

	sessionReqData := entity.SessionRequestData{
		UserID:   userSession.UserID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserDevice.UserAgent,
			IP:        reqData.UserDevice.IP,
		},
	}

	ctx, createSessionSpan := tracing.StartSpan(ctx, "create_session")
	tokenData, err := u.sessionMgr.CreateSession(ctx, sessionReqData)
	if err != nil {
		tracing.RecordError(createSessionSpan, err)
		createSessionSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.String("user.id", userSession.UserID))
		u.metrics.RecordRefreshTokensError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToCreateUserSession.Error()))
		return entity.SessionTokens{}, domain.ErrFailedToCreateUserSession
	}

	createSessionSpan.End()

	log.Info("tokens created", slog.String("user.id", userSession.UserID))

	u.metrics.RecordRefreshTokensSuccess(ctx, clientID)

	return tokenData, nil
}

func (u *Auth) GetJWKS(ctx context.Context, clientID string) (entity.JWKS, error) {
	const method = "usecase.Auth.GetJWKS"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("client.id", clientID),
	)

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
	)

	u.metrics.RecordJWKSRetrievalAttempt(ctx, clientID)

	ctx, getPublicKeySpan := tracing.StartSpan(ctx, "get_public_key")

	publicKey, err := u.tokenMgr.PublicKey(clientID)
	if err != nil {
		tracing.RecordError(getPublicKeySpan, err)
		getPublicKeySpan.End()

		e.LogError(ctx, log, domain.ErrFailedToGetPublicKey, err)
		u.metrics.RecordJWKSRetrievalError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetPublicKey.Error()))
		return entity.JWKS{}, domain.ErrFailedToGetPublicKey
	}

	getPublicKeySpan.End()

	ctx, getKeyIDSpan := tracing.StartSpan(ctx, "get_key_id")
	kid, err := u.tokenMgr.Kid(clientID)
	if err != nil {
		tracing.RecordError(getKeyIDSpan, err)
		getKeyIDSpan.End()

		e.LogError(ctx, log, domain.ErrFailedToGetKeyID, err)
		u.metrics.RecordJWKSRetrievalError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetKeyID.Error()))
		return entity.JWKS{}, domain.ErrFailedToGetKeyID
	}

	getKeyIDSpan.End()

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
		u.metrics.RecordJWKSRetrievalError(ctx, clientID, attribute.String("error.type", domain.ErrFailedToGetJWKS.Error()))
		return entity.JWKS{}, domain.ErrFailedToGetJWKS
	}

	// Construct a JWKS with the JWK
	jwksSlice := []entity.JWK{jwk}
	jwks := u.constructJWKS(jwksSlice...)

	span.AddEvent("JWKS constructed")
	log.Info("JWKS retrieved")

	u.metrics.RecordJWKSRetrievalSuccess(ctx, clientID)

	return jwks, nil
}

// verifyPassword checks if password is correct
func (u *Auth) verifyPassword(ctx context.Context, userData entity.User, password string) error {
	const method = "usecase.Auth.verifyPassword"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("user.id", userData.ID),
	)

	ctx, getUserDataSpan := tracing.StartSpan(ctx, "get_user_data")
	userData, err := u.userMgr.GetUserData(ctx, userData.ID)
	if err != nil {
		tracing.RecordError(getUserDataSpan, err)
		getUserDataSpan.End()
		return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
	}

	getUserDataSpan.End()

	span.AddEvent("verifying_password")
	matched, err := u.tokenMgr.PasswordMatch(userData.PasswordHash, password)
	if err != nil {
		tracing.RecordError(span, err)
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if !matched {
		return domain.ErrInvalidCredentials
	}

	return nil
}

func (u *Auth) sendEmailWithToken(ctx context.Context, tokenData entity.VerificationToken, templateType entity.EmailTemplateType) error {
	const method = "usecase.Auth.sendEmailWithToken"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("user.email", tokenData.Email),
		tracing.String("email.template_type", string(templateType)),
	)

	emailData := mail.Data{
		TemplateType: templateType,
		Subject:      templateType.Subject(),
		Recipient:    tokenData.Email,
		Data: map[string]string{
			"Recipient": tokenData.Email,
			"URL":       fmt.Sprintf("%s%s", tokenData.Endpoint, tokenData.Token),
		},
	}

	span.AddEvent("Sending email")
	if err := u.mailService.SendEmail(ctx, emailData); err != nil {
		tracing.RecordError(span, err)
		return err
	}
	return nil
}

func (u *Auth) handleTokenProcessing(
	ctx context.Context,
	token string,
	emailTemplateType entity.EmailTemplateType,
) (entity.VerificationToken, error) {
	const method = "usecase.Auth.handleTokenProcessing"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.AddEvent("Getting token data")
	tokenData, err := u.verificationMgr.GetTokenData(ctx, token)
	if err != nil {
		return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToGetVerificationTokenData, err)
	}

	span.AddEvent("Checking if token is expired")
	if tokenData.ExpiresAt.Before(time.Now()) {
		u.log.Info("token expired",
			slog.String("user.id", tokenData.UserID),
			slog.String("token", tokenData.Token))

		span.AddEvent("Token expired, deleting token")
		if err = u.verificationMgr.DeleteToken(ctx, tokenData.Token); err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToDeleteVerificationToken, err)
		}

		userData := entity.User{
			ID:    tokenData.UserID,
			Email: tokenData.Email,
		}

		span.AddEvent("Creating new token")
		tokenData, err = u.verificationMgr.CreateToken(ctx, userData, tokenData.Endpoint, tokenData.Type)
		if err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToCreateVerificationToken, err)
		}

		span.AddEvent("Sending email with new token")
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

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	span.SetAttributes(
		tracing.String("user.id", userData.ID),
	)

	span.AddEvent("Validating password change")
	err := u.validatePasswordChanged(userData.PasswordHash, reqData.UpdatedPassword)
	if err != nil {
		tracing.RecordError(span, err)
		return err
	}

	span.AddEvent("Hashing updated password")
	updatedPassHash, err := u.tokenMgr.HashPassword(reqData.UpdatedPassword)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGeneratePasswordHash, err)
	}

	updatedUser := entity.User{
		ID:           userData.ID,
		PasswordHash: updatedPassHash,
		UpdatedAt:    time.Now(),
	}

	span.AddEvent("Updating user data")
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
