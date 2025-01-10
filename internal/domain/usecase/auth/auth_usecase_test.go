package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	"github.com/rshelekhov/sso/internal/lib/logger/handler/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuth_Login(t *testing.T) {
	ctx := context.Background()

	appID := "test-app-id"
	userID := "test-user-id"
	email := "test@example.com"
	password := "test-password"
	hashedPassword := "password-hash"
	userAgent := "test-agent"
	ip := "127.0.0.1"

	validUser := entity.User{
		ID:           userID,
		Email:        email,
		PasswordHash: hashedPassword,
		AppID:        appID,
	}

	validReqData := &entity.UserRequestData{
		Email:    email,
		Password: password,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: userAgent,
			IP:        ip,
		},
	}

	expectedTokens := entity.SessionTokens{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}

	tests := []struct {
		name         string
		reqData      *entity.UserRequestData
		mockBehavior func(
			userMgr *mocks.UserdataManager,
			tokenMgr *mocks.TokenManager,
			sessionMgr *mocks.SessionManager,
			txMgr *mocks.TransactionManager,
		)
		expectedError  error
		expectedTokens entity.SessionTokens
	}{
		{
			name:    "Success",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(validUser, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, password).
					Once().
					Return(true, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				sessionMgr.EXPECT().CreateSession(ctx, mock.MatchedBy(func(data entity.SessionRequestData) bool {
					return data.UserID == userID &&
						data.AppID == appID &&
						data.UserDevice.UserAgent == userAgent &&
						data.UserDevice.IP == ip
				})).
					Once().
					Return(expectedTokens, nil)
			},
			expectedError:  nil,
			expectedTokens: expectedTokens,
		},
		{
			name:    "User Not Found",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError:  domain.ErrUserNotFound,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to get user by email",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(entity.User{}, fmt.Errorf("some error"))
			},
			expectedError:  domain.ErrFailedToGetUserByEmail,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Invalid Password",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(validUser, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, password).
					Once().
					Return(false, nil)
			},
			expectedError:  domain.ErrInvalidCredentials,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to get user data",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("some error"))
			},
			expectedError:  domain.ErrFailedToVerifyPassword,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to verify password",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(validUser, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, password).
					Once().
					Return(false, fmt.Errorf("some error"))
			},
			expectedError:  domain.ErrFailedToVerifyPassword,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to create session",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(validUser, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, password).
					Once().
					Return(true, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				sessionMgr.EXPECT().CreateSession(ctx, mock.MatchedBy(func(data entity.SessionRequestData) bool {
					return data.UserID == userID &&
						data.AppID == appID &&
						data.UserDevice.UserAgent == userAgent &&
						data.UserDevice.IP == ip
				})).
					Once().
					Return(entity.SessionTokens{}, fmt.Errorf("some error"))
			},
			expectedError:  fmt.Errorf("some error"),
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to commit transaction",
			reqData: validReqData,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, email).
					Once().
					Return(validUser, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(validUser, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, password).
					Once().
					Return(true, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError:  fmt.Errorf("some error"),
			expectedTokens: entity.SessionTokens{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			tokenMgr := mocks.NewTokenManager(t)
			sessionMgr := mocks.NewSessionManager(t)
			txMgr := mocks.NewTransactionManager(t)
			mailService := mocks.NewMailService(t)
			verificationMgr := mocks.NewVerificationManager(t)
			db := mocks.NewStorage(t)

			tt.mockBehavior(userMgr, tokenMgr, sessionMgr, txMgr)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, txMgr, sessionMgr, userMgr, mailService, tokenMgr, verificationMgr, db)

			tokens, err := auth.Login(ctx, appID, tt.reqData)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedTokens, tokens)
			}
		})
	}
}

func TestAuth_RegisterUser(t *testing.T) {
	ctx := context.Background()

	appID := "test-app-id"
	email := "test@example.com"
	password := "password123"
	hashedPassword := "hashed_password"
	endpoint := "https://example.com/verify/"
	tokenStr := "test-verification-token"
	tokenType := entity.TokenTypeVerifyEmail

	validReqData := &entity.UserRequestData{
		Email:    email,
		Password: password,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: "test-agent",
			IP:        "127.0.0.1",
		},
	}

	expectedTokens := entity.SessionTokens{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}

	tokenData := entity.VerificationToken{
		Token:    tokenStr,
		Email:    email,
		Endpoint: endpoint,
	}

	tests := []struct {
		name         string
		reqData      *entity.UserRequestData
		endpoint     string
		mockBehavior func(
			userMgr *mocks.UserdataManager,
			tokenMgr *mocks.TokenManager,
			sessionMgr *mocks.SessionManager,
			txMgr *mocks.TransactionManager,
			verificationMgr *mocks.VerificationManager,
			mailService *mocks.MailService,
			storage *mocks.Storage,
		)
		expectedError  error
		expectedTokens entity.SessionTokens
	}{
		{
			name:     "Success - register user",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				storage.EXPECT().RegisterUser(ctx, mock.MatchedBy(func(user entity.User) bool {
					return user.Email == email &&
						user.AppID == appID &&
						user.PasswordHash == hashedPassword
				})).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, mock.AnythingOfType("entity.SessionRequestData")).
					Once().
					Return(expectedTokens, nil)

				verificationMgr.EXPECT().CreateToken(ctx, mock.AnythingOfType("entity.User"), endpoint, tokenType).
					Once().
					Return(tokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					email,
				).
					Once().
					Return(nil)
			},
			expectedError:  nil,
			expectedTokens: expectedTokens,
		},
		{
			name:     "Success — replace soft deleted user",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusSoftDeleted.String(), nil)

				storage.EXPECT().ReplaceSoftDeletedUser(ctx, mock.MatchedBy(func(user entity.User) bool {
					return user.Email == email &&
						user.AppID == appID &&
						user.PasswordHash == hashedPassword
				})).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, mock.AnythingOfType("entity.SessionRequestData")).
					Once().
					Return(expectedTokens, nil)

				verificationMgr.EXPECT().CreateToken(ctx, mock.AnythingOfType("entity.User"), endpoint, tokenType).
					Once().
					Return(tokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					email,
				).
					Once().
					Return(nil)
			},
			expectedError:  nil,
			expectedTokens: expectedTokens,
		},
		{
			name:     "User already exists",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusActive.String(), nil)
			},
			expectedError:  domain.ErrUserAlreadyExists,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to hash password",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return("", errors.New("failed to hash password"))
			},
			expectedError:  errors.New("failed to hash password"),
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to get user status by email",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return("", domain.ErrFailedToGetUserStatusByEmail)
			},
			expectedError:  domain.ErrFailedToGetUserStatusByEmail,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to replace soft deleted user",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusSoftDeleted.String(), nil)

				storage.EXPECT().ReplaceSoftDeletedUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(domain.ErrFailedToReplaceSoftDeletedUser)
			},
			expectedError:  domain.ErrFailedToReplaceSoftDeletedUser,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to register user",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				storage.EXPECT().RegisterUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(domain.ErrFailedToRegisterUser)
			},
			expectedError:  domain.ErrFailedToRegisterUser,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Unknown user status",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return("some unknown user status", nil)
			},
			expectedError:  domain.ErrUnknownUserStatus,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to create user session",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, "test@example.com").
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				storage.EXPECT().RegisterUser(ctx, mock.MatchedBy(func(user entity.User) bool {
					return user.Email == email &&
						user.AppID == appID &&
						user.PasswordHash == hashedPassword
				})).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, mock.AnythingOfType("entity.SessionRequestData")).
					Once().
					Return(entity.SessionTokens{}, domain.ErrFailedToCreateUserSession)
			},
			expectedError:  domain.ErrFailedToCreateUserSession,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to create verification token",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, email).
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				storage.EXPECT().RegisterUser(ctx, mock.MatchedBy(func(user entity.User) bool {
					return user.Email == email &&
						user.AppID == appID &&
						user.PasswordHash == hashedPassword
				})).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, mock.AnythingOfType("entity.SessionRequestData")).
					Once().
					Return(expectedTokens, nil)

				verificationMgr.EXPECT().CreateToken(ctx, mock.AnythingOfType("entity.User"), endpoint, tokenType).
					Once().
					Return(entity.VerificationToken{}, domain.ErrFailedToCreateVerificationToken)
			},
			expectedError:  domain.ErrFailedToCreateVerificationToken,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to send verification email",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByEmail(ctx, "test@example.com").
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				storage.EXPECT().RegisterUser(ctx, mock.MatchedBy(func(user entity.User) bool {
					return user.Email == email &&
						user.AppID == appID &&
						user.PasswordHash == hashedPassword
				})).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, mock.AnythingOfType("entity.SessionRequestData")).
					Once().
					Return(expectedTokens, nil)

				verificationMgr.EXPECT().CreateToken(ctx, mock.AnythingOfType("entity.User"), endpoint, tokenType).
					Once().
					Return(tokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					email,
				).
					Once().
					Return(domain.ErrFailedToSendVerificationEmail)
			},
			expectedError:  domain.ErrFailedToSendVerificationEmail,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:     "Failed to commit transaction",
			reqData:  validReqData,
			endpoint: endpoint,
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
				sessionMgr *mocks.SessionManager,
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				tokenMgr.EXPECT().HashPassword(password).
					Once().
					Return(hashedPassword, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError:  fmt.Errorf("some error"),
			expectedTokens: entity.SessionTokens{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			tokenMgr := mocks.NewTokenManager(t)
			sessionMgr := mocks.NewSessionManager(t)
			txMgr := mocks.NewTransactionManager(t)
			mailService := mocks.NewMailService(t)
			verificationMgr := mocks.NewVerificationManager(t)
			db := mocks.NewStorage(t)

			tt.mockBehavior(userMgr, tokenMgr, sessionMgr, txMgr, verificationMgr, mailService, db)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, txMgr, sessionMgr, userMgr, mailService, tokenMgr, verificationMgr, db)

			tokens, err := auth.RegisterUser(ctx, appID, tt.reqData, tt.endpoint)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedTokens, tokens)
			}
		})
	}
}

func TestAuth_VerifyEmail(t *testing.T) {
	ctx := context.Background()

	userID := "test-user-id"
	appID := "test-app-id"
	endpoint := "https://example.com/verify"
	email := "test@example.com"
	tokenStr := "test-verification-token"
	tokenType := entity.TokenTypeVerifyEmail

	userData := entity.User{
		ID:    "test-user-id",
		AppID: "test-app-id",
		Email: "test@example.com",
	}

	expectedTokenData := entity.VerificationToken{
		Token:     tokenStr,
		UserID:    userID,
		AppID:     appID,
		Endpoint:  endpoint,
		Email:     email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	expiredTokenData := entity.VerificationToken{
		Token:     tokenStr,
		UserID:    userID,
		AppID:     appID,
		Endpoint:  endpoint,
		Email:     email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}

	newTokenData := entity.VerificationToken{
		Token:     "new-test-verification-token",
		UserID:    userID,
		AppID:     appID,
		Endpoint:  endpoint,
		Email:     email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	tests := []struct {
		name         string
		mockBehavior func(
			txMgr *mocks.TransactionManager,
			verificationMgr *mocks.VerificationManager,
			mailService *mocks.MailService,
			storage *mocks.Storage,
		)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expectedTokenData, nil)

				storage.EXPECT().MarkEmailVerified(ctx, expectedTokenData.UserID, expectedTokenData.AppID).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Token expired, email resent",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, tokenStr).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(newTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					email,
				).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Verification token not found",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(entity.VerificationToken{}, domain.ErrVerificationTokenNotFound)
			},
			expectedError: domain.ErrVerificationTokenNotFound,
		},
		{
			name: "Failed to get verification token",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(entity.VerificationToken{}, fmt.Errorf("some error"))
			},
			expectedError: errors.New("some error"),
		},
		{
			name: "Failed to delete verification token",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, tokenStr).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToDeleteVerificationToken,
		},
		{
			name: "Failed to create verification token",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, tokenStr).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(entity.VerificationToken{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToCreateVerificationToken,
		},
		{
			name: "Failed to send verification email",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, tokenStr).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(newTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string"), "test@example.com").
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToSendEmail,
		},
		{
			name: "Failed to mark email as verified",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, tokenStr).
					Once().
					Return(expectedTokenData, nil)

				storage.EXPECT().MarkEmailVerified(ctx, expectedTokenData.UserID, expectedTokenData.AppID).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToMarkEmailVerified,
		},
		{
			name: "Failed to commit transaction",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				storage *mocks.Storage,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError: errors.New("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txMgr := mocks.NewTransactionManager(t)
			verificationMgr := mocks.NewVerificationManager(t)
			mailService := mocks.NewMailService(t)
			db := mocks.NewStorage(t)

			tt.mockBehavior(txMgr, verificationMgr, mailService, db)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, txMgr, nil, nil, mailService, nil, verificationMgr, db)

			_, err := auth.VerifyEmail(ctx, tokenStr)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuth_ResetPassword(t *testing.T) {
	ctx := context.Background()

	appID := "test-app-id"
	endpoint := "https://example.com/change-password"
	tokenStr := "test-verification-token"
	tokenType := entity.TokenTypeResetPassword

	userData := entity.User{
		ID:        "test-user-id",
		AppID:     appID,
		Email:     "test@example.com",
		UpdatedAt: time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	reqData := &entity.ResetPasswordRequestData{
		Email: userData.Email,
	}

	expectedTokenData := entity.VerificationToken{
		Token:     tokenStr,
		UserID:    userData.ID,
		AppID:     userData.AppID,
		Endpoint:  endpoint,
		Email:     userData.Email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	tests := []struct {
		name         string
		mockBehavior func(
			userMgr *mocks.UserdataManager,
			verificationMgr *mocks.VerificationManager,
			mailService *mocks.MailService,
		)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, reqData.Email).
					Once().
					Return(userData, nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(expectedTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					reqData.Email,
				).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "User not found",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, reqData.Email).
					Once().
					Return(entity.User{}, storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Failed to get user by email",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, reqData.Email).
					Once().
					Return(entity.User{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToGetUserByEmail,
		},
		{
			name: "Failed to create verification token",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, reqData.Email).
					Once().
					Return(userData, nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(entity.VerificationToken{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToCreateVerificationToken,
		},
		{
			name: "Failed to send reset password email",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
			) {
				userMgr.EXPECT().GetUserByEmail(ctx, appID, reqData.Email).
					Once().
					Return(userData, nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(expectedTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					reqData.Email,
				).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToSendResetPasswordEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			verificationMgr := mocks.NewVerificationManager(t)
			mailService := mocks.NewMailService(t)

			tt.mockBehavior(userMgr, verificationMgr, mailService)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, nil, nil, userMgr, mailService, nil, verificationMgr, nil)

			err := auth.ResetPassword(ctx, appID, reqData, endpoint)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuth_ChangePassword(t *testing.T) {
	ctx := context.Background()

	userID := "test-user-id"
	appID := "test-app-id"

	userData := entity.User{
		ID:        userID,
		AppID:     appID,
		Email:     "email@example.com",
		UpdatedAt: time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	hashedPassword := "hashed-password"
	newPasswordHash := "new-password-hash"

	endpoint := "https://example.com/change-password"

	tokenStr := "test-reset-password-token"
	tokenType := entity.TokenTypeResetPassword

	reqData := &entity.ChangePasswordRequestData{
		ResetPasswordToken: tokenStr,
		UpdatedPassword:    "new-password",
	}

	expectedTokenData := entity.VerificationToken{
		Token:     tokenStr,
		UserID:    userData.ID,
		AppID:     userData.AppID,
		Endpoint:  endpoint,
		Email:     userData.Email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	expiredTokenData := entity.VerificationToken{
		Token:     tokenStr,
		UserID:    userData.ID,
		AppID:     userData.AppID,
		Endpoint:  endpoint,
		Email:     userData.Email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}

	newTokenData := entity.VerificationToken{
		Token:     "new-test-verification-token",
		UserID:    userData.ID,
		AppID:     userData.AppID,
		Endpoint:  endpoint,
		Email:     userData.Email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	tests := []struct {
		name         string
		mockBehavior func(
			txMgr *mocks.TransactionManager,
			verificationMgr *mocks.VerificationManager,
			mailService *mocks.MailService,
			userMgr *mocks.UserdataManager,
			tokenMgr *mocks.TokenManager,
		)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{
						ID:           userData.ID,
						Email:        userData.Email,
						PasswordHash: hashedPassword,
						AppID:        userData.AppID,
						UpdatedAt:    time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					}, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, reqData.UpdatedPassword).
					Once().
					Return(false, nil)

				tokenMgr.EXPECT().HashPassword(reqData.UpdatedPassword).
					Once().
					Return(newPasswordHash, nil)

				userMgr.EXPECT().UpdateUserData(ctx, mock.MatchedBy(func(u entity.User) bool {
					return u.ID == userData.ID &&
						u.PasswordHash == newPasswordHash &&
						u.AppID == userData.AppID
				})).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Token expired, email resent",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, reqData.ResetPasswordToken).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(newTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					userData.Email,
				).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to get token data",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(entity.VerificationToken{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToGetVerificationTokenData,
		},
		{
			name: "Failed to delete token",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, reqData.ResetPasswordToken).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToDeleteVerificationToken,
		},
		{
			name: "Failed to create token",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, reqData.ResetPasswordToken).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(entity.VerificationToken{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToCreateVerificationToken,
		},
		{
			name: "Failed to send reset password email",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expiredTokenData, nil)

				verificationMgr.EXPECT().DeleteToken(ctx, reqData.ResetPasswordToken).
					Once().
					Return(nil)

				verificationMgr.EXPECT().CreateToken(ctx, userData, endpoint, tokenType).
					Once().
					Return(newTokenData, nil)

				mailService.EXPECT().GetTemplatesPath().
					Once().
					Return(mail.DefaultTemplatesPath)

				mailService.EXPECT().SendHTML(
					ctx,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("string"),
					userData.Email,
				).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToSendEmail,
		},
		{
			name: "Failed to get user data",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToGetUserData,
		},
		{
			name: "Failed to check password hash match",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{
						ID:           userData.ID,
						Email:        userData.Email,
						PasswordHash: hashedPassword,
						AppID:        userData.AppID,
						UpdatedAt:    time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					}, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, reqData.UpdatedPassword).
					Once().
					Return(false, fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToCheckPasswordHashMatch,
		},
		{
			name: "No password changes detected",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{
						ID:           userData.ID,
						Email:        userData.Email,
						PasswordHash: hashedPassword,
						AppID:        userData.AppID,
						UpdatedAt:    time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					}, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, reqData.UpdatedPassword).
					Once().
					Return(true, nil)
			},
			expectedError: domain.ErrNoPasswordChangesDetected,
		},
		{
			name: "Failed to generate password hash",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{
						ID:           userData.ID,
						Email:        userData.Email,
						PasswordHash: hashedPassword,
						AppID:        userData.AppID,
						UpdatedAt:    time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					}, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, reqData.UpdatedPassword).
					Once().
					Return(false, nil)

				tokenMgr.EXPECT().HashPassword(reqData.UpdatedPassword).
					Once().
					Return("", fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToGeneratePasswordHash,
		},
		{
			name: "Failed to update user data",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				verificationMgr.EXPECT().GetTokenData(ctx, reqData.ResetPasswordToken).
					Once().
					Return(expectedTokenData, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{
						ID:           userData.ID,
						Email:        userData.Email,
						PasswordHash: hashedPassword,
						AppID:        userData.AppID,
						UpdatedAt:    time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					}, nil)

				tokenMgr.EXPECT().PasswordMatch(hashedPassword, reqData.UpdatedPassword).
					Once().
					Return(false, nil)

				tokenMgr.EXPECT().HashPassword(reqData.UpdatedPassword).
					Once().
					Return(newPasswordHash, nil)

				userMgr.EXPECT().UpdateUserData(ctx, mock.MatchedBy(func(u entity.User) bool {
					return u.ID == userData.ID &&
						u.PasswordHash == newPasswordHash &&
						u.AppID == userData.AppID
				})).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToUpdateUser,
		},
		{
			name: "Failed to commit transaction",
			mockBehavior: func(
				txMgr *mocks.TransactionManager,
				verificationMgr *mocks.VerificationManager,
				mailService *mocks.MailService,
				userMgr *mocks.UserdataManager,
				tokenMgr *mocks.TokenManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError: fmt.Errorf("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txMgr := mocks.NewTransactionManager(t)
			verificationMgr := mocks.NewVerificationManager(t)
			mailService := mocks.NewMailService(t)
			userMgr := mocks.NewUserdataManager(t)
			tokenMgr := mocks.NewTokenManager(t)

			tt.mockBehavior(txMgr, verificationMgr, mailService, userMgr, tokenMgr)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, txMgr, nil, userMgr, mailService, tokenMgr, verificationMgr, nil)

			_, err := auth.ChangePassword(ctx, userData.AppID, reqData)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuth_LogoutUser(t *testing.T) {
	ctx := context.Background()

	appID := "test-app-id"
	userID := "test-user-id"
	deviceID := "test-device-id"
	userAgent := "test-agent"
	ip := "127.0.0.1"

	userDeviceReqData := entity.UserDeviceRequestData{
		UserAgent: userAgent,
		IP:        ip,
	}

	tests := []struct {
		name          string
		mockBehavior  func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager) {
				tokenMgr.EXPECT().ExtractUserIDFromContext(ctx, appID).
					Once().
					Return(userID, nil)

				sessionMgr.EXPECT().GetUserDeviceID(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return(deviceID, nil)

				sessionMgr.EXPECT().DeleteSession(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					DeviceID:   deviceID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to extract user ID from context",
			mockBehavior: func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager) {
				tokenMgr.EXPECT().ExtractUserIDFromContext(ctx, appID).
					Once().
					Return("", domain.ErrFailedToExtractUserIDFromContext)
			},
			expectedError: domain.ErrFailedToExtractUserIDFromContext,
		},
		{
			name: "User device not found",
			mockBehavior: func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager) {
				tokenMgr.EXPECT().ExtractUserIDFromContext(ctx, appID).
					Once().
					Return(userID, nil)

				sessionMgr.EXPECT().GetUserDeviceID(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return("", domain.ErrUserDeviceNotFound)
			},
			expectedError: domain.ErrUserDeviceNotFound,
		},
		{
			name: "Failed to get user device ID",
			mockBehavior: func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager) {
				tokenMgr.EXPECT().ExtractUserIDFromContext(ctx, appID).
					Once().
					Return(userID, nil)

				sessionMgr.EXPECT().GetUserDeviceID(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return("", fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToGetDeviceID,
		},
		{
			name: "Failed to delete session",
			mockBehavior: func(tokenMgr *mocks.TokenManager, sessionMgr *mocks.SessionManager) {
				tokenMgr.EXPECT().ExtractUserIDFromContext(ctx, appID).
					Once().
					Return(userID, nil)

				sessionMgr.EXPECT().GetUserDeviceID(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return(deviceID, nil)

				sessionMgr.EXPECT().DeleteSession(ctx, entity.SessionRequestData{
					UserID:     userID,
					AppID:      appID,
					DeviceID:   deviceID,
					UserDevice: userDeviceReqData,
				}).
					Once().
					Return(fmt.Errorf("some error"))
			},
			expectedError: domain.ErrFailedToDeleteSession,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenMgr := mocks.NewTokenManager(t)
			sessionMgr := mocks.NewSessionManager(t)

			tt.mockBehavior(tokenMgr, sessionMgr)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, nil, sessionMgr, nil, nil, tokenMgr, nil, nil)

			err := auth.LogoutUser(ctx, appID, &userDeviceReqData)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuth_RefreshTokens(t *testing.T) {
	ctx := context.Background()

	userID := "test-user-id"
	appID := "test-app-id"
	deviceID := "test-device-id"
	refreshTokenStr := "test-refresh-token"
	userAgent := "test-agent"
	ip := "127.0.0.1"

	userDeviceReqData := entity.UserDeviceRequestData{
		UserAgent: userAgent,
		IP:        ip,
	}

	reqData := entity.RefreshTokenRequestData{
		RefreshToken: refreshTokenStr,
		UserDevice:   userDeviceReqData,
	}

	sessionReqData := entity.SessionRequestData{
		UserID: userID,
		AppID:  appID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: userAgent,
			IP:        ip,
		},
	}

	userSession := entity.Session{
		UserID:        userID,
		AppID:         appID,
		DeviceID:      deviceID,
		RefreshToken:  refreshTokenStr,
		LastVisitedAt: time.Now(),
		ExpiresAt:     time.Now().Add(15 * time.Minute),
	}

	expectedSessionTokens := entity.SessionTokens{
		AccessToken:  "test-access-token",
		RefreshToken: "new-test-refresh-token",
		Domain:       "test-domain",
		Path:         "test-path",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		HTTPOnly:     true,
		AdditionalFields: map[string]string{
			"key": "value",
		},
	}

	tests := []struct {
		name                  string
		mockBehavior          func(sessionMgr *mocks.SessionManager)
		expectedError         error
		expectedSessionTokens entity.SessionTokens
	}{
		{
			name: "Success",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(userSession, nil)

				sessionMgr.EXPECT().DeleteRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, sessionReqData).
					Once().
					Return(expectedSessionTokens, nil)
			},
			expectedError:         nil,
			expectedSessionTokens: expectedSessionTokens,
		},
		{
			name: "Session not found",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(entity.Session{}, domain.ErrSessionNotFound)
			},
			expectedError:         domain.ErrSessionNotFound,
			expectedSessionTokens: entity.SessionTokens{},
		},
		{
			name: "Session expired",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(entity.Session{}, domain.ErrSessionExpired)
			},
			expectedError:         domain.ErrSessionExpired,
			expectedSessionTokens: entity.SessionTokens{},
		},
		{
			name: "User device not found",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(entity.Session{}, domain.ErrUserDeviceNotFound)
			},
			expectedError:         domain.ErrUserDeviceNotFound,
			expectedSessionTokens: entity.SessionTokens{},
		},
		{
			name: "Failed to get session by refresh token",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(entity.Session{}, domain.ErrFailedToGetSessionByRefreshToken)
			},
			expectedError:         domain.ErrFailedToGetSessionByRefreshToken,
			expectedSessionTokens: entity.SessionTokens{},
		},
		{
			name: "Failed to delete refresh token",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(userSession, nil)

				sessionMgr.EXPECT().DeleteRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(domain.ErrFailedToDeleteRefreshToken)
			},
			expectedError:         domain.ErrFailedToDeleteRefreshToken,
			expectedSessionTokens: entity.SessionTokens{},
		},
		{
			name: "Failed to create session",
			mockBehavior: func(sessionMgr *mocks.SessionManager) {
				sessionMgr.EXPECT().GetSessionByRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(userSession, nil)

				sessionMgr.EXPECT().DeleteRefreshToken(ctx, reqData.RefreshToken).
					Once().
					Return(nil)

				sessionMgr.EXPECT().CreateSession(ctx, sessionReqData).
					Once().
					Return(expectedSessionTokens, domain.ErrFailedToCreateUserSession)
			},
			expectedError:         domain.ErrFailedToCreateUserSession,
			expectedSessionTokens: entity.SessionTokens{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionMgr := mocks.NewSessionManager(t)

			tt.mockBehavior(sessionMgr)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, nil, sessionMgr, nil, nil, nil, nil, nil)

			sessionTokens, err := auth.RefreshTokens(ctx, appID, &reqData)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSessionTokens, sessionTokens)
			}
		})
	}
}

func TestAuth_GetJWKS(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"

	// Test data
	rsaKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	ecdsaKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(123),
		Y:     big.NewInt(456),
	}

	kid := "test-kid"
	signingMethod := "RS256"
	jwksTTL := 24 * time.Hour

	expectedRSAJWKS := entity.JWKS{
		Keys: []entity.JWK{
			{
				Kty: "RSA",
				Alg: signingMethod,
				Use: "alg",
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
			},
		},
		TTL: jwksTTL,
	}

	expectedECDSAJWKS := entity.JWKS{
		Keys: []entity.JWK{
			{
				Kty: "EC",
				Alg: signingMethod,
				Use: "alg",
				Kid: kid,
				Crv: ecdsaKey.Curve.Params().Name,
				X:   base64.RawURLEncoding.EncodeToString(ecdsaKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(ecdsaKey.Y.Bytes()),
			},
		},
		TTL: jwksTTL,
	}

	tests := []struct {
		name          string
		mockBehavior  func(tokenMgr *mocks.TokenManager)
		expectedError error
		expectedJWKS  entity.JWKS
	}{
		{
			name: "Success with RSA key",
			mockBehavior: func(tokenMgr *mocks.TokenManager) {
				tokenMgr.EXPECT().PublicKey(appID).
					Once().
					Return(rsaKey, nil)

				tokenMgr.EXPECT().Kid(appID).
					Once().
					Return(kid, nil)

				tokenMgr.EXPECT().SigningMethod().
					Once().
					Return(signingMethod)

				tokenMgr.EXPECT().JWKSTTL().
					Once().
					Return(jwksTTL)
			},
			expectedError: nil,
			expectedJWKS:  expectedRSAJWKS,
		},
		{
			name: "Success with ECDSA key",
			mockBehavior: func(tokenMgr *mocks.TokenManager) {
				tokenMgr.EXPECT().PublicKey(appID).
					Once().
					Return(ecdsaKey, nil)

				tokenMgr.EXPECT().Kid(appID).
					Once().
					Return(kid, nil)

				tokenMgr.EXPECT().SigningMethod().
					Once().
					Return(signingMethod)

				tokenMgr.EXPECT().JWKSTTL().
					Once().
					Return(jwksTTL)
			},
			expectedError: nil,
			expectedJWKS:  expectedECDSAJWKS,
		},
		{
			name: "Failed to get public key",
			mockBehavior: func(tokenMgr *mocks.TokenManager) {
				tokenMgr.EXPECT().PublicKey(appID).
					Once().
					Return(nil, domain.ErrFailedToGetPublicKey)
			},
			expectedError: domain.ErrFailedToGetPublicKey,
			expectedJWKS:  entity.JWKS{},
		},
		{
			name: "Failed to get key ID",
			mockBehavior: func(tokenMgr *mocks.TokenManager) {
				tokenMgr.EXPECT().PublicKey(appID).
					Once().
					Return(rsaKey, nil)

				tokenMgr.EXPECT().Kid(appID).
					Once().
					Return("", domain.ErrFailedToGetKeyID)
			},
			expectedError: domain.ErrFailedToGetKeyID,
			expectedJWKS:  entity.JWKS{},
		},
		{
			name: "Unsupported key type",
			mockBehavior: func(tokenMgr *mocks.TokenManager) {
				tokenMgr.EXPECT().PublicKey(appID).
					Once().
					Return("unsupported-key-type", nil)

				tokenMgr.EXPECT().Kid(appID).
					Once().
					Return(kid, nil)

				tokenMgr.EXPECT().SigningMethod().
					Once().
					Return(signingMethod)
			},
			expectedError: domain.ErrFailedToGetJWKS,
			expectedJWKS:  entity.JWKS{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenMgr := mocks.NewTokenManager(t)

			tt.mockBehavior(tokenMgr)

			log := slogdiscard.NewDiscardLogger()

			auth := NewUsecase(log, nil, nil, nil, nil, tokenMgr, nil, nil)

			jwks, err := auth.GetJWKS(ctx, appID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedJWKS, jwks)
			}
		})
	}
}
