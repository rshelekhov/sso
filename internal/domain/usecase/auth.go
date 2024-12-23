package usecase

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"github.com/rshelekhov/sso/src/lib/e"
	"html/template"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/rshelekhov/sso/src/lib/constant/le"
)

type AuthUsecase struct {
	log                 *slog.Logger
	sessionService      SessionService
	userService         UserService
	mailService         MailService
	tokenService        TokenService
	verificationService VerificationService
	storage             AuthStorage
}

type (
	AuthProvider interface {
		Login(ctx context.Context, appID string, reqData *entity.UserRequestData) (entity.SessionTokens, error)
		RegisterUser(ctx context.Context, appID string, reqData *entity.UserRequestData, confirmEmailEndpoint string) (entity.SessionTokens, error)
		VerifyEmail(ctx context.Context, verificationToken string) error
		ResetPassword(ctx context.Context, appID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error
		ChangePassword(ctx context.Context, appID string, reqData *entity.ChangePasswordRequestData) error
		LogoutUser(ctx context.Context, appID string, reqData *entity.UserDeviceRequestData) error
		RefreshTokens(ctx context.Context, appID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error)
		GetJWKS(ctx context.Context, appID string) (entity.JWKS, error)
	}

	SessionService interface {
		CreateSession(ctx context.Context, reqData entity.SessionRequestData) (entity.SessionTokens, error)
		GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error)
		GetUserDeviceID(ctx context.Context, reqData entity.SessionRequestData) (string, error)
		DeleteSession(ctx context.Context, sessionReqData entity.SessionRequestData) error
		DeleteRefreshToken(ctx context.Context, refreshToken string) error
	}

	UserService interface {
		GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error)
		GetUserStatusByEmail(ctx context.Context, email string) (string, error)
		GetUserData(ctx context.Context, appID, userID string) (entity.User, error)
		UpdateUser(ctx context.Context, user entity.User) error
	}

	MailService interface {
		SendPlainText(ctx context.Context, subject, body, recipient string) error
		SendHTML(ctx context.Context, subject, html, recipient string) error
		GetTemplatesPath() string
	}

	TokenService interface {
		HashPassword(password string) (string, error)
		PasswordMatch(hash, password string) (bool, error)
		ExtractUserIDFromContext(ctx context.Context, appID string) (string, error)
		PublicKey(appID string) (interface{}, error)
		Kid(appID string) (string, error)
		JWKSTTL() time.Duration
		SigningMethod() string
	}

	VerificationService interface {
		CreateToken(ctx context.Context, user entity.User, verificationEndpoint string, tokenType entity.VerificationTokenType) (entity.VerificationToken, error)
		GetTokenData(ctx context.Context, token string) (entity.VerificationToken, error)
		DeleteToken(ctx context.Context, token string) error
	}

	AuthStorage interface {
		// Transaction(ctx context.Context, fn func(storage AuthStorage) error) error
		ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error
		RegisterUser(ctx context.Context, user entity.User) error
		MarkEmailVerified(ctx context.Context, userID, appID string) error
	}
)

func NewAuthUsecase(
	log *slog.Logger,
	ss SessionService,
	us UserService,
	ms MailService,
	ts TokenService,
	vs VerificationService,
	storage AuthStorage,
) *AuthUsecase {
	return &AuthUsecase{
		log:                 log,
		sessionService:      ss,
		userService:         us,
		mailService:         ms,
		tokenService:        ts,
		verificationService: vs,
		storage:             storage,
	}
}

// Login checks if user with given credentials exists in the system
func (u *AuthUsecase) Login(ctx context.Context, appID string, reqData *entity.UserRequestData) (entity.SessionTokens, error) {
	const method = "usecase.appUsecase.Login"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	userData, err := u.userService.GetUserByEmail(ctx, appID, reqData.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.HandleError(ctx, log, domain.ErrUserNotFound, err)
			return entity.SessionTokens{}, domain.ErrUserNotFound
		}

		e.HandleError(ctx, log, domain.ErrFailedToGetUserByEmail, err)
		return entity.SessionTokens{}, err
	}

	if err = u.verifyPassword(ctx, userData, reqData.Password); err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			e.HandleError(ctx, log, domain.ErrInvalidCredentials, err, slog.Any("userID", userData.ID))
			return entity.SessionTokens{}, domain.ErrInvalidCredentials
		}

		e.HandleError(ctx, log, domain.ErrFailedToVerifyPassword, err, slog.Any("userID", userData.ID))
		return entity.SessionTokens{}, err
	}

	tokenData := entity.SessionTokens{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		sessionReqData := entity.SessionRequestData{
			UserID: userData.ID,
			AppID:  userData.AppID,
			UserDevice: entity.UserDeviceRequestData{
				UserAgent: reqData.UserDevice.UserAgent,
				IP:        reqData.UserDevice.IP,
			},
		}

		tokenData, err = u.sessionService.CreateSession(ctx, sessionReqData)
		if err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any("userID", userData.ID))
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		return nil
	}); err != nil {
		e.HandleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any("userID", userData.ID))
		return entity.SessionTokens{}, err
	}

	log.Info("user authenticated, tokens created",
		slog.String("userID", userData.ID),
	)

	return tokenData, nil
}

// RegisterUser creates new user in the system and returns jwtoken
func (u *AuthUsecase) RegisterUser(ctx context.Context, appID string, reqData *entity.UserRequestData, verifyEmailEndpoint string) (entity.SessionTokens, error) {
	const method = "usecase.appUsecase.RegisterUser"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	hash, err := u.tokenService.HashPassword(reqData.Password)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToGeneratePasswordHash, err)
		return entity.SessionTokens{}, err
	}

	newUser := entity.NewUser(reqData.Email, hash, appID)

	authTokenData := entity.SessionTokens{}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		userStatus, err := u.userService.GetUserStatusByEmail(ctx, newUser.Email)
		if err != nil {
			return err
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			return domain.ErrUserAlreadyExists
		case entity.UserStatusSoftDeleted.String():
			if err = u.storage.ReplaceSoftDeletedUser(ctx, newUser); err != nil {
				e.HandleError(ctx, log, domain.ErrFailedToReplaceSoftDeletedUser, err)
				return err
			}
		case entity.UserStatusNotFound.String():
			if err = u.storage.RegisterUser(ctx, newUser); err != nil {
				e.HandleError(ctx, log, domain.ErrFailedToCreateUser, err)
				return err
			}
		default:
			return fmt.Errorf("%w: %s", domain.ErrUnknownUserStatus, userStatus)
		}

		sessionReqData := entity.SessionRequestData{
			UserID: newUser.ID,
			AppID:  newUser.AppID,
			UserDevice: entity.UserDeviceRequestData{
				UserAgent: reqData.UserDevice.UserAgent,
				IP:        reqData.UserDevice.IP,
			},
		}

		authTokenData, err = u.sessionService.CreateSession(ctx, sessionReqData)
		if err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any("userID", newUser.ID))
			return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
		}

		tokenData, err := u.verificationService.CreateToken(ctx, newUser, verifyEmailEndpoint, entity.TokenTypeVerifyEmail)
		if err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToCreateVerificationToken, err)
			return err
		}

		if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeVerifyEmail); err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToSendVerificationEmail, err)
			return err
		}

		return nil
	}); err != nil {
		e.HandleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any("userID", newUser.ID))
		return entity.SessionTokens{}, err
	}

	log.Info("newUser and tokens created, verification email sent",
		slog.String("userID", newUser.ID),
	)

	return authTokenData, nil
}

func (u *AuthUsecase) VerifyEmail(ctx context.Context, verificationToken string) error {
	const method = "usecase.appUsecase.VerifyEmail"

	log := u.log.With(
		slog.String("method", method),
	)

	if err := u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err := u.handleTokenProcessing(ctx, verificationToken, entity.EmailTemplateTypeVerifyEmail)
		if err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToProcessToken, err, slog.Any("token", verificationToken))
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token == verificationToken {
			// It means that verification token was not expired and not generated new token with email resent
			if err = u.storage.MarkEmailVerified(ctx, tokenData.UserID, tokenData.AppID); err != nil {
				e.HandleError(ctx, log, domain.ErrFailedToMarkEmailVerified, err, slog.Any("verificationToken", verificationToken))
				return err
			}
			log.Info("email verified", slog.String("userID", tokenData.UserID))
			return nil
		}

		return nil
	}); err != nil {
		e.HandleError(ctx, log, le.ErrFailedToCommitTransaction, err)
		return err
	}

	return nil
}

func (u *AuthUsecase) ResetPassword(ctx context.Context, appID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error {
	const method = "usecase.appUsecase.ResetPassword"

	log := u.log.With(
		slog.String("method", method),
		slog.String("email", reqData.Email),
	)

	userData, err := u.userService.GetUserByEmail(ctx, appID, reqData.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			e.HandleError(ctx, log, domain.ErrUserNotFound, err, slog.Any("email", reqData.Email))
			return domain.ErrUserNotFound
		}

		e.HandleError(ctx, u.log, domain.ErrFailedToGetUserByEmail, err, slog.Any("email", reqData.Email))
		return err
	}

	tokenData, err := u.verificationService.CreateToken(ctx, userData, changePasswordEndpoint, entity.TokenTypeResetPassword)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToCreateVerificationToken, err)
		return err
	}

	if err = u.sendEmailWithToken(ctx, tokenData, entity.EmailTemplateTypeResetPassword); err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToSendResetPasswordEmail, err)
		return err
	}

	log.Info("reset password email sent",
		slog.String("userID", userData.ID),
		slog.String("email", reqData.Email),
	)

	return nil
}

func (u *AuthUsecase) ChangePassword(ctx context.Context, appID string, reqData *entity.ChangePasswordRequestData) error {
	const method = "usecase.appUsecase.ChangePassword"

	log := u.log.With(
		slog.String("method", method),
	)

	if err := u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		tokenData, err := u.handleTokenProcessing(ctx, reqData.ResetPasswordToken, entity.EmailTemplateTypeResetPassword)
		if err != nil {
			e.HandleError(ctx, log, domain.ErrFailedToProcessToken, err, slog.Any("token", reqData.ResetPasswordToken))
			return fmt.Errorf("%w: %w", domain.ErrFailedToProcessToken, err)
		}

		if tokenData.Token == reqData.ResetPasswordToken {
			// It means that reset password token was not expired and not generated new token with email resent
			userDataFromDB, err := u.userService.GetUserData(ctx, appID, tokenData.UserID)
			if err != nil {
				e.HandleError(ctx, log, domain.ErrFailedToGetUserData, err, slog.Any("userID", tokenData.UserID))
				return err
			}

			if err = u.checkPasswordHashAndUpdate(ctx, appID, userDataFromDB, reqData); err != nil {
				return err
			}

			log.Info("password changed", slog.String("userID", userDataFromDB.ID))
			return nil
		}

		return nil
	}); err != nil {
		e.HandleError(ctx, log, le.ErrFailedToCommitTransaction, err)
		return err
	}

	return nil
}

func (u *AuthUsecase) LogoutUser(ctx context.Context, appID string, reqData *entity.UserDeviceRequestData) error {
	const method = "usecase.appUsecase.LogoutUser"

	log := u.log.With(
		slog.String("method", method),
	)

	userID, err := u.tokenService.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	sessionReqData := entity.SessionRequestData{
		UserID: userID,
		AppID:  appID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserAgent,
			IP:        reqData.IP,
		},
	}

	// Check if the device exists
	sessionReqData.DeviceID, err = u.sessionService.GetUserDeviceID(ctx, sessionReqData)
	if err != nil {
		if errors.Is(err, domain.ErrUserDeviceNotFound) {
			e.HandleError(ctx, log, domain.ErrUserDeviceNotFound, err)
			return domain.ErrUserDeviceNotFound
		}

		e.HandleError(ctx, log, domain.ErrFailedToGetDeviceID, err)
		return err
	}

	log.Info("user logged out",
		slog.String("userID", sessionReqData.UserID),
		slog.String("deviceID", sessionReqData.DeviceID),
	)

	if err = u.sessionService.DeleteSession(ctx, sessionReqData); err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToDeleteSession, err)
		return domain.ErrFailedToDeleteSession
	}

	return nil
}

func (u *AuthUsecase) RefreshTokens(ctx context.Context, appID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error) {
	const method = "usecase.appUsecase.RefreshTokens"

	log := u.log.With(
		slog.String("method", method),
	)

	userSession, err := u.sessionService.GetSessionByRefreshToken(ctx, reqData.RefreshToken)

	switch {
	case errors.Is(err, domain.ErrSessionNotFound):
		e.HandleError(ctx, log, domain.ErrSessionNotFound, err)
		return entity.SessionTokens{}, domain.ErrSessionNotFound
	case errors.Is(err, domain.ErrSessionExpired):
		e.HandleError(ctx, log, domain.ErrSessionExpired, err)
		return entity.SessionTokens{}, domain.ErrSessionExpired
	case errors.Is(err, domain.ErrUserDeviceNotFound):
		e.HandleError(ctx, log, domain.ErrUserDeviceNotFound, err)
		return entity.SessionTokens{}, domain.ErrUserDeviceNotFound
	case err != nil:
		e.HandleError(ctx, log, domain.ErrFailedToCheckSessionAndDevice, err)
		return entity.SessionTokens{}, fmt.Errorf("%w: %w", domain.ErrFailedToCheckSessionAndDevice, err)
	}

	if err = u.sessionService.DeleteRefreshToken(ctx, reqData.RefreshToken); err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToDeleteRefreshToken, err)
		return entity.SessionTokens{}, err
	}

	sessionReqData := entity.SessionRequestData{
		UserID: userSession.UserID,
		AppID:  appID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: reqData.UserDevice.UserAgent,
			IP:        reqData.UserDevice.IP,
		},
	}

	tokenData, err := u.sessionService.CreateSession(ctx, sessionReqData)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToCreateUserSession, err, slog.Any("userID", userSession.UserID))
		return entity.SessionTokens{}, fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
	}

	log.Info("tokens created", slog.Any("userID", userSession.UserID))

	return tokenData, nil
}

func (u *AuthUsecase) GetJWKS(ctx context.Context, appID string) (entity.JWKS, error) {
	const method = "usecase.appUsecase.GetJWKS"

	log := u.log.With(
		slog.String("method", method),
	)

	publicKey, err := u.tokenService.PublicKey(appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToGetPublicKey, err)
		return entity.JWKS{}, err
	}

	kid, err := u.tokenService.Kid(appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToGetKeyID, err)
		return entity.JWKS{}, err
	}

	jwk := entity.JWK{
		Alg: u.tokenService.SigningMethod(),
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
		return entity.JWKS{}, domain.ErrFailedToGetJWKS
	}

	// Construct a JWKS with the JWK
	jwksSlice := []entity.JWK{jwk}
	jwks := u.constructJWKS(jwksSlice...)

	log.Info("JWKS retrieved")

	return jwks, nil
}

// verifyPassword checks if password is correct
func (u *AuthUsecase) verifyPassword(ctx context.Context, userData entity.User, password string) error {
	const method = "usecase.AuthUsecase.verifyPassword"

	userData, err := u.userService.GetUserData(ctx, userData.AppID, userData.ID)
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
	}

	matched, err := u.tokenService.PasswordMatch(userData.PasswordHash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if !matched {
		return domain.ErrInvalidCredentials
	}

	return nil
}

func (u *AuthUsecase) sendEmailWithToken(ctx context.Context, tokenData entity.VerificationToken, templateType entity.EmailTemplateType) error {
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

func (u *AuthUsecase) handleTokenProcessing(
	ctx context.Context,
	token string,
	emailTemplateType entity.EmailTemplateType,
) (entity.VerificationToken, error) {
	tokenData, err := u.verificationService.GetTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrVerificationTokenNotFound) {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrVerificationTokenNotFound, err)
		}

		return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToGetVerificationTokenData, err)
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		u.log.Info("token expired",
			slog.Any("userID", tokenData.UserID),
			slog.Any("token", tokenData.Token))

		if err = u.verificationService.DeleteToken(ctx, tokenData.Token); err != nil {
			return entity.VerificationToken{}, fmt.Errorf("%w: %w", domain.ErrFailedToDeleteVerificationToken, err)
		}

		userData := entity.User{
			ID:    tokenData.UserID,
			AppID: tokenData.AppID,
			Email: tokenData.Email,
		}

		tokenData, err = u.verificationService.CreateToken(ctx, userData, tokenData.Endpoint, tokenData.Type)
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

func (u *AuthUsecase) checkPasswordHashAndUpdate(
	ctx context.Context,
	appID string,
	userData entity.User,
	reqData *entity.ChangePasswordRequestData,
) error {
	const method = "usecase.AuthUsecase.checkPasswordHashAndUpdate"

	err := u.validatePasswordChanged(userData.PasswordHash, reqData.UpdatedPassword)
	if err != nil {
		return err
	}

	updatedPassHash, err := u.tokenService.HashPassword(reqData.UpdatedPassword)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGeneratePasswordHash, err)
	}

	updatedUser := entity.User{
		ID:           userData.ID,
		PasswordHash: updatedPassHash,
		AppID:        appID,
		UpdatedAt:    time.Now(),
	}

	if err = u.userService.UpdateUser(ctx, updatedUser); err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToUpdateUser, err)
	}

	return nil
}

func (u *AuthUsecase) validatePasswordChanged(hash, password string) error {
	const method = "usecase.AuthUsecase.validatePasswordChanged"

	matched, err := u.tokenService.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if matched {
		return domain.ErrNoPasswordChangesDetected
	}

	return nil
}

func (u *AuthUsecase) constructJWKS(jwks ...entity.JWK) entity.JWKS {
	return entity.JWKS{
		Keys: jwks,
		TTL:  u.tokenService.JWKSTTL(),
	}
}
