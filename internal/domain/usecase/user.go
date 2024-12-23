package usecase

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/lib/constant/le"
	"github.com/rshelekhov/sso/src/lib/e"
	"log/slog"
	"time"
)

type UserUsecase struct {
	log            *slog.Logger
	requestIDMgr   ContextManager
	appIDMgr       ContextManager
	appValidator   AppValidator
	sessionService UserSessionService
	userService    DomainUserService
	passwordMgr    PasswordManager
	identityMgr    IdentityManager
}

type (
	UserProvider interface {
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

	UserSessionService interface {
		DeleteUserSessions(ctx context.Context, user entity.User) error
	}

	DomainUserService interface {
		GetUserByID(ctx context.Context, appID, userID string) (entity.User, error)
		GetUserData(ctx context.Context, appID, userID string) (entity.User, error)
		GetUserStatusByEmail(ctx context.Context, email string) (string, error)
		GetUserStatusByID(ctx context.Context, userID string) (string, error)
		UpdateUser(ctx context.Context, user entity.User) error
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
)

func NewUserUsecase(
	log *slog.Logger,
	reqIDMgr ContextManager,
	appIDMgr ContextManager,
	av AppValidator,
	ss UserSessionService,
	us DomainUserService,
	pm PasswordManager,
	im IdentityManager,
) *UserUsecase {
	return &UserUsecase{
		log:            log,
		requestIDMgr:   reqIDMgr,
		appIDMgr:       appIDMgr,
		appValidator:   av,
		sessionService: ss,
		userService:    us,
		passwordMgr:    pm,
		identityMgr:    im,
	}
}

func (u *UserUsecase) GetUserByID(ctx context.Context, appID string) (entity.User, error) {
	const method = "usecase.UserUsecase.GetUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return entity.User{}, domain.ErrFailedToExtractUserIDFromContext
	}

	userData, err := u.userService.GetUserByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.HandleError(ctx, log, domain.ErrUserNotFound, err, slog.Any("userID", userID))
			return entity.User{}, domain.ErrUserNotFound
		}
		e.HandleError(ctx, log, domain.ErrFailedToGetUser, err, slog.Any("userID", userID))
		return entity.User{}, fmt.Errorf("%w: %w", domain.ErrFailedToGetUserByID, err)
	}

	log.Info("user found by ID", slog.String("userID", userID))

	return userData, nil
}

func (u *UserUsecase) UpdateUser(ctx context.Context, appID string, data *entity.UserRequestData) error {
	const method = "usecase.UserUsecase.UpdateUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	userDataFromDB, err := u.userService.GetUserData(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			e.HandleError(ctx, log, domain.ErrUserNotFound, err, slog.Any("userID", userID))
			return domain.ErrUserNotFound
		}
		e.HandleError(ctx, log, domain.ErrFailedToGetUserData, err, slog.Any("userID", userID))
		return fmt.Errorf("%w: %w", domain.ErrFailedToGetUserData, err)
	}

	if err = u.updateUserFields(ctx, appID, data, userDataFromDB); err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToUpdateUser, err, slog.Any("userID", userID))
		return fmt.Errorf("%w: %w", domain.ErrFailedToUpdateUser, err)
	}

	log.Info("user updated", slog.String("userID", userID))

	return nil
}

func (u *UserUsecase) DeleteUser(ctx context.Context, appID string) error {
	const method = "usecase.UserUsecase.DeleteUser"

	log := u.log.With(slog.String("method", method))

	userID, err := u.identityMgr.ExtractUserIDFromContext(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, domain.ErrFailedToExtractUserIDFromContext, err)
		return domain.ErrFailedToExtractUserIDFromContext
	}

	userData := entity.User{
		ID:        userID,
		AppID:     appID,
		DeletedAt: time.Now(),
	}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		userStatus, err := u.userService.GetUserStatusByID(ctx, userData.ID)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrFailedToCheckIfUserExists, err)
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			if err = u.cleanupUserData(ctx, userData); err != nil {
				return fmt.Errorf("%w: %w", domain.ErrFailedToCleanupUserData, err)
			}
			return nil
		case entity.UserStatusSoftDeleted.String(), entity.UserStatusNotFound.String():
			return domain.ErrUserNotFound
		default:
			return fmt.Errorf("%w: %s", domain.ErrUnknownUserStatus, userStatus)
		}
	}); err != nil {
		e.HandleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any("userID", userData.ID))
		return err
	}

	log.Info("user soft-deleted", slog.String("userID", userData.ID))

	return nil
}

func (u *UserUsecase) updateUserFields(
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

	err := u.userService.UpdateUser(ctx, updatedUser)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserUsecase) handlePasswordUpdate(
	data *entity.UserRequestData,
	userDataFromDB entity.User,
	updatedUser *entity.User,
) error {
	const method = "usecase.UserUsecase.handlePasswordUpdate"

	if data.UpdatedPassword == "" {
		return nil
	}

	// Check if the current password is correct
	if err := u.validateCurrentPassword(userDataFromDB.PasswordHash, data.Password); err != nil {
		return err
	}

	// Check if the new password does not match the current password
	if err := u.validatePasswordChanged(userDataFromDB.PasswordHash, data.UpdatedPassword); err != nil {
		return err
	}

	hash, err := u.passwordMgr.HashPassword(data.UpdatedPassword)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGeneratePasswordHash, err)
	}

	updatedUser.PasswordHash = hash

	return nil
}

func (u *UserUsecase) validateCurrentPassword(hash, password string) error {
	const method = "usecase.UserUsecase.validateCurrentPassword"

	matched, err := u.passwordMgr.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if !matched {
		return domain.ErrPasswordsDoNotMatch
	}

	return nil
}

func (u *UserUsecase) validatePasswordChanged(hash, password string) error {
	const method = "usecase.UserUsecase.validatePasswordChanged"

	matched, err := u.passwordMgr.PasswordMatch(hash, password)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToCheckPasswordHashMatch, err)
	}

	if matched {
		return domain.ErrNoPasswordChangesDetected
	}

	return nil
}

func (u *UserUsecase) handleEmailUpdate(ctx context.Context, userDataFromDB entity.User, updatedUser *entity.User) error {
	const method = "usecase.UserUsecase.handleEmailUpdate"

	if updatedUser.Email == "" {
		return nil
	}

	if updatedUser.Email == userDataFromDB.Email {
		return domain.ErrNoEmailChangesDetected
	}

	userStatus, err := u.userService.GetUserStatusByEmail(ctx, updatedUser.Email)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetUserStatusByEmail, err)
	}

	if userStatus == entity.UserStatusActive.String() {
		return domain.ErrEmailAlreadyTaken
	}

	return nil
}

func (u *UserUsecase) cleanupUserData(ctx context.Context, user entity.User) error {
	if err := u.userService.DeleteUser(ctx, user); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteUser, err)
	}

	if err := u.sessionService.DeleteUserSessions(ctx, user); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteAllUserSessions, err)
	}

	if err := u.userService.DeleteUserTokens(ctx, user.AppID, user.ID); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToDeleteUserTokens, err)
	}

	return nil
}
