package user

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/lib/e"
)

type User struct {
	log          *slog.Logger
	txMgr        TransactionManager
	requestIDMgr ContextManager
	appIDMgr     ContextManager
	appValidator AppValidator
	sessionMgr   SessionManager
	userMgr      UserdataManager
	passwordMgr  PasswordManager
	identityMgr  IdentityManager
}

type (
	Usecase interface {
		GetUserByID(ctx context.Context, appID string) (entity.User, error)
		UpdateUser(ctx context.Context, appID string, data *entity.UserRequestData) error
		DeleteUser(ctx context.Context, appID string) error
	}

	ContextManager interface {
		FromContext(ctx context.Context) (string, bool)
		ToContext(ctx context.Context, value string) context.Context
	}

	AppValidator interface {
		ValidateAppID(ctx context.Context, appID string) error
	}

	SessionManager interface {
		DeleteUserSessions(ctx context.Context, user entity.User) error
		DeleteUserDevices(ctx context.Context, user entity.User) error
	}

	UserdataManager interface {
		GetUserByID(ctx context.Context, appID, userID string) (entity.User, error)
		GetUserData(ctx context.Context, appID, userID string) (entity.User, error)
		GetUserStatusByEmail(ctx context.Context, email string) (string, error)
		GetUserStatusByID(ctx context.Context, userID string) (string, error)
		UpdateUserData(ctx context.Context, user entity.User) error
		DeleteUser(ctx context.Context, user entity.User) error
		DeleteUserTokens(ctx context.Context, appID, userID string) error
	}

	PasswordManager interface {
		HashPassword(password string) (string, error)
		PasswordMatch(hash, password string) (bool, error)
	}

	IdentityManager interface {
		ExtractUserIDFromContext(ctx context.Context, appID string) (string, error)
	}

	TransactionManager interface {
		WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	}
)

func NewUsecase(
	log *slog.Logger,
	tm TransactionManager,
	reqIDMgr ContextManager,
	appIDMgr ContextManager,
	av AppValidator,
	ss SessionManager,
	us UserdataManager,
	pm PasswordManager,
	im IdentityManager,
) *User {
	return &User{
		log:          log,
		txMgr:        tm,
		requestIDMgr: reqIDMgr,
		appIDMgr:     appIDMgr,
		appValidator: av,
		sessionMgr:   ss,
		userMgr:      us,
		passwordMgr:  pm,
		identityMgr:  im,
	}
}

func (u *User) GetUserByID(ctx context.Context, appID string) (entity.User, error) {
	const method = "usecase.User.GetUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return entity.User{}, domain.ErrFailedToExtractUserIDFromContext
	}

	userData, err := u.userMgr.GetUserByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err, slog.Any("userID", userID))
			return entity.User{}, domain.ErrUserNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetUser, err, slog.Any("userID", userID))
		return entity.User{}, fmt.Errorf("%w: %w", domain.ErrFailedToGetUserByID, err)
	}

	log.Info("user found by ID", slog.String("userID", userID))

	return userData, nil
}

func (u *User) UpdateUser(ctx context.Context, appID string, data *entity.UserRequestData) error {
	const method = "usecase.User.UpdateUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	userDataFromDB, err := u.userMgr.GetUserData(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.LogError(ctx, log, domain.ErrUserNotFound, err, slog.Any("userID", userID))
			return domain.ErrUserNotFound
		}

		e.LogError(ctx, log, domain.ErrFailedToGetUserData, err, slog.Any("userID", userID))
		return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
	}

	if err = u.updateUserFields(ctx, appID, data, userDataFromDB); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToUpdateUser, err, slog.Any("userID", userID))
		return fmt.Errorf("%w: %w", domain.ErrFailedToUpdateUser, err)
	}

	log.Info("user updated", slog.String("userID", userID))

	return nil
}

func (u *User) DeleteUser(ctx context.Context, appID string) error {
	const method = "usecase.User.DeleteUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	userData := entity.User{
		ID:        userID,
		AppID:     appID,
		DeletedAt: time.Now(),
	}

	if err = u.txMgr.WithinTransaction(ctx, func(txCtx context.Context) error {
		userStatus, err := u.userMgr.GetUserStatusByID(txCtx, userData.ID)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserStatusByID, err)
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			if err = u.cleanupUserData(txCtx, userData); err != nil {
				return fmt.Errorf("%w: %w", domain.ErrFailedToCleanupUserData, err)
			}
			return nil
		case entity.UserStatusSoftDeleted.String(), entity.UserStatusNotFound.String():
			return domain.ErrUserNotFound
		default:
			return fmt.Errorf("%w: %s", domain.ErrUnknownUserStatus, userStatus)
		}
	}); err != nil {
		e.LogError(ctx, log, domain.ErrFailedToCommitTransaction, err, slog.Any("userID", userData.ID))
		return err
	}

	log.Info("user soft-deleted", slog.String("userID", userData.ID))

	return nil
}

func (u *User) updateUserFields(
	ctx context.Context,
	appID string,
	data *entity.UserRequestData,
	userDataFromDB entity.User,
) error {
	updatedUser := entity.User{
		ID:        userDataFromDB.ID,
		Email:     data.Email,
		AppID:     appID,
		UpdatedAt: time.Now(),
	}

	if err := u.handlePasswordUpdate(data, userDataFromDB, &updatedUser); err != nil {
		return err
	}

	if err := u.handleEmailUpdate(ctx, userDataFromDB, &updatedUser); err != nil {
		return err
	}

	err := u.userMgr.UpdateUserData(ctx, updatedUser)
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToUpdateUser, err)
	}

	return nil
}

func (u *User) handlePasswordUpdate(
	data *entity.UserRequestData,
	userDataFromDB entity.User,
	updatedUser *entity.User,
) error {
	const method = "usecase.User.handlePasswordUpdate"

	if data.UpdatedPassword == "" {
		return nil
	}

	// Check if the current password is provided
	if data.Password == "" {
		return domain.ErrCurrentPasswordRequired
	}

	// Check if the current password is correct
	if err := u.validateCurrentPassword(userDataFromDB.PasswordHash, data.Password); err != nil {
		return err
	}

	// Check if the new password does not match the current password
	if err := u.validateNewPassword(userDataFromDB.PasswordHash, data.UpdatedPassword); err != nil {
		return err
	}

	hash, err := u.passwordMgr.HashPassword(data.UpdatedPassword)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGeneratePasswordHash, err)
	}

	updatedUser.PasswordHash = hash

	return nil
}

func (u *User) validateCurrentPassword(hash, password string) error {
	const method = "usecase.User.validateCurrentPassword"

	matched, err := u.passwordMgr.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if !matched {
		return domain.ErrPasswordsDoNotMatch
	}

	return nil
}

func (u *User) validateNewPassword(hash, password string) error {
	const method = "usecase.User.validateNewPassword"

	matched, err := u.passwordMgr.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if matched {
		return domain.ErrNoPasswordChangesDetected
	}

	return nil
}

func (u *User) handleEmailUpdate(ctx context.Context, userDataFromDB entity.User, updatedUser *entity.User) error {
	const method = "usecase.User.handleEmailUpdate"

	if updatedUser.Email == "" {
		return nil
	}

	if updatedUser.Email == userDataFromDB.Email {
		return domain.ErrNoEmailChangesDetected
	}

	userStatus, err := u.userMgr.GetUserStatusByEmail(ctx, updatedUser.Email)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetUserStatusByEmail, err)
	}

	if userStatus == entity.UserStatusActive.String() {
		return domain.ErrEmailAlreadyTaken
	}

	return nil
}

func (u *User) cleanupUserData(ctx context.Context, user entity.User) error {
	if err := u.userMgr.DeleteUser(ctx, user); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteUser, err)
	}

	if err := u.sessionMgr.DeleteUserSessions(ctx, user); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteAllUserSessions, err)
	}

	if err := u.sessionMgr.DeleteUserDevices(ctx, user); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteUserDevices, err)
	}

	if err := u.userMgr.DeleteUserTokens(ctx, user.AppID, user.ID); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteUserTokens, err)
	}

	return nil
}
