package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt"
	"github.com/rshelekhov/sso/internal/port"
	"log/slog"
	"time"
)

type Storage interface {
}

type SessionService interface{}

type Usecase struct {
	log            *slog.Logger
	storage        Storage
	appValidator   appvalidator.Validator
	sessionService SessionService
}

func NewUserUsecase(
	log *slog.Logger,
	storage Storage,
	av appvalidator.Validator,
	ss SessionService,
) *Usecase {
	return &Usecase{
		log:            log,
		storage:        storage,
		appValidator:   av,
		sessionService: ss,
	}
}

var (
	ErrFailedToDeleteAllUserSessions = errors.New("failed to delete all sessions")
	ErrFailedToValidateAppID         = errors.New("failed to validate app ID")
)

func (u *Usecase) GetUserByID(ctx context.Context, data *entity.UserRequestData) (entity.User, error) {
	const method = "usecase.Usecase.GetUser"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return entity.User{}, err
	}

	log := u.log.With(
		slog.String("requestID", reqID),
		slog.String("method", method),
	)

	if err = u.appValidator.ValidateAppID(ctx, data.AppID); err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			handleError(ctx, log, domain.ErrAppNotFound, err, slog.Any("appID", data.AppID))
			return entity.User{}, domain.ErrAppNotFound
		}

		handleError(ctx, log, ErrFailedToValidateAppID, err, slog.Any("appID", data.AppID))
		return entity.User{}, err
	}

	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return entity.User{}, le.ErrFailedToGetUserIDFromToken
	}

	user, err := u.storage.GetUserByID(ctx, userID, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
			return entity.User{}, le.ErrUserNotFound
		}

		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
		return entity.User{}, le.ErrFailedToGetUser
	}

	log.Info("user found by ID", slog.String(key.UserID, userID))

	return user, nil
}

func (u *Usecase) UpdateUser(ctx context.Context, data *entity.UserRequestData) error {
	const method = "usecase.Usecase.UpdateUser"

	reqID, err := u.getReqID(ctx, method)
	if err != nil {
		return err
	}

	log := u.log.With(
		slog.String(key.RequestID, reqID),
		slog.String(key.Method, method),
	)

	if err = u.appValidator.ValidateAppID(ctx, data.AppID); err != nil {
		return err
	}

	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	userDataFromDB, err := u.storage.GetUserData(ctx, userID, data.AppID)
	if err != nil {
		if errors.Is(err, le.ErrUserNotFound) {
			handleError(ctx, log, le.ErrUserNotFound, err, slog.Any(key.UserID, userID))
			return le.ErrUserNotFound
		}

		handleError(ctx, log, le.ErrFailedToGetUser, err, slog.Any(key.UserID, userID))
		return le.ErrFailedToGetUser
	}

	if err = updateUserFields(ctx, u, data, userDataFromDB, log); err != nil {
		return err
	}

	log.Info("user updated", slog.String(key.UserID, userID))

	return nil
}

func updateUserFields(ctx context.Context, u *Usecase, data *entity.UserRequestData, userDataFromDB entity.User, log *slog.Logger) error {
	updatedUser := entity.User{
		ID:        userDataFromDB.ID,
		Email:     data.Email,
		AppID:     data.AppID,
		UpdatedAt: time.Now(),
	}

	if err := u.handlePasswordUpdate(ctx, data, userDataFromDB, &updatedUser, log); err != nil {
		return err
	}

	if err := u.handleEmailUpdate(ctx, userDataFromDB, &updatedUser, log); err != nil {
		return err
	}

	err := u.storage.UpdateUser(ctx, updatedUser)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToUpdateUser, err, slog.Any(key.UserID, userDataFromDB.ID))
		return le.ErrInternalServerError
	}

	return nil
}

func (u *Usecase) handlePasswordUpdate(
	ctx context.Context,
	data *entity.UserRequestData,
	userDataFromDB entity.User,
	updatedUser *entity.User,
	log *slog.Logger,
) error {
	if data.UpdatedPassword == "" {
		return nil
	}

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

	updatedPassHash, err := jwt.PasswordHash(data.UpdatedPassword, u.tokenService.PasswordHashParams)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGeneratePasswordHash, err, slog.Any(key.UserID, userDataFromDB.ID))
		return le.ErrInternalServerError
	}

	updatedUser.PasswordHash = updatedPassHash
	return nil
}

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

func (u *Usecase) handleEmailUpdate(ctx context.Context, userDataFromDB entity.User, updatedUser *entity.User, log *slog.Logger) error {
	if updatedUser.Email == "" {
		return nil
	}

	if updatedUser.Email == userDataFromDB.Email {
		handleError(ctx, log, le.ErrNoEmailChangesDetected, nil, slog.Any(key.UserID, userDataFromDB.ID))
		return le.ErrNoEmailChangesDetected
	}

	userStatus, err := u.storage.GetUserStatusByEmail(ctx, updatedUser.Email)
	if err != nil {
		return err
	}

	if userStatus == entity.UserStatusActive.String() {
		return le.ErrEmailAlreadyTaken
	}

	return nil
}

func (u *Usecase) DeleteUser(ctx context.Context, data *entity.UserRequestData) error {
	const method = "usecase.Usecase.DeleteUser"

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

	userID, err := u.tokenService.GetUserID(ctx, data.AppID, key.UserID)
	if err != nil {
		handleError(ctx, log, le.ErrFailedToGetUserIDFromToken, err)
		return le.ErrFailedToGetUserIDFromToken
	}

	user := entity.User{
		ID:        userID,
		AppID:     data.AppID,
		DeletedAt: time.Now(),
	}

	if err = u.storage.Transaction(ctx, func(_ port.AuthStorage) error {
		userStatus, err := u.storage.GetUserStatusByID(ctx, user.ID)
		if err != nil {
			return err
		}

		switch userStatus {
		case entity.UserStatusActive.String():
			if err := u.cleanupUserData(ctx, log, user); err != nil {
				return err
			}
			return nil
		case entity.UserStatusSoftDeleted.String(), entity.UserStatusNotFound.String():
			return le.ErrUserNotFound
		default:
			return fmt.Errorf("%s: unknown user status: %s", method, userStatus)
		}
	}); err != nil {
		handleError(ctx, log, le.ErrFailedToCommitTransaction, err, slog.Any(key.UserID, user.ID))
		return err
	}

	log.Info("user soft-deleted", slog.String(key.UserID, user.ID))

	return nil
}

func (u *Usecase) cleanupUserData(ctx context.Context, log *slog.Logger, user entity.User) error {
	if err := u.storage.DeleteUser(ctx, user); err != nil {
		handleError(ctx, log, le.ErrFailedToDeleteUser, err, slog.Any(key.UserID, user.ID))
		return le.ErrFailedToDeleteUser
	}

	if err := u.sessionService.DeleteAllUserSessions(ctx, user); err != nil {
		handleError(ctx, log, ErrFailedToDeleteAllUserSessions, err, slog.Any(key.UserID, user.ID))
		return ErrFailedToDeleteAllUserSessions
	}

	if err := u.storage.DeleteAllTokens(ctx, user.ID, user.AppID); err != nil {
		handleError(ctx, log, le.ErrFailedToDeleteTokens, err, slog.Any(key.UserID, user.ID))
		return le.ErrFailedToDeleteTokens
	}

	return nil
}
