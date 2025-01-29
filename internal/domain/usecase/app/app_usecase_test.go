package app

import (
	"context"
	"errors"
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/app/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/logger/handler/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAppUsecase_RegisterApp(t *testing.T) {
	ctx := context.Background()

	appName := "test-app"

	tests := []struct {
		name          string
		appName       string
		mockBehavior  func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager)
		expectedError error
	}{
		{
			name:    "Success",
			appName: appName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "Empty app name",
			appName: "",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				// No calls expected
			},
			expectedError: domain.ErrAppNameIsEmpty,
		},
		{
			name:    "App already exists",
			appName: appName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(storage.ErrAppAlreadyExists)
			},
			expectedError: domain.ErrAppAlreadyExists,
		},
		{
			name:    "Failed to register app",
			appName: appName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToRegisterApp,
		},
		{
			name:    "Failed to generate private key",
			appName: appName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(errors.New("key generation error"))

				// Expect DeleteApp to be called for rollback
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(nil)
			},
			expectedError: domain.ErrFailedToGenerateAndSavePrivateKey,
		},
		{
			name:    "Failed to delete app",
			appName: appName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(errors.New("key generation error"))

				// Expect DeleteApp to be called for rollback
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(domain.ErrFailedToDeleteApp)
			},
			expectedError: domain.ErrFailedToDeleteApp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := mocks.NewStorage(t)
			keyManagerMock := mocks.NewKeyManager(t)

			tt.mockBehavior(storageMock, keyManagerMock)

			log := slogdiscard.NewDiscardLogger()

			app := NewUsecase(log, keyManagerMock, storageMock)

			err := app.RegisterApp(ctx, tt.appName)

			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}

func TestAppUsecase_DeleteApp(t *testing.T) {
	ctx := context.Background()

	appID := "test-app-id"
	secretHash := "test-secret-hash"

	tests := []struct {
		name          string
		mockBehavior  func(storageMock *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.MatchedBy(func(data entity.AppData) bool {
					return data.ID == appID && data.Secret == secretHash
				})).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "App not found",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(storage.ErrAppNotFound)
			},
			expectedError: domain.ErrAppNotFound,
		},
		{
			name: "Delete failed",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Once().
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToDeleteApp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := mocks.NewStorage(t)

			tt.mockBehavior(storageMock)

			log := slogdiscard.NewDiscardLogger()

			app := NewUsecase(log, nil, storageMock)

			err := app.DeleteApp(ctx, appID, secretHash)

			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}
