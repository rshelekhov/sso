package app

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/app/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/logger/handler/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestRegisterApp(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		appName       string
		mockBehavior  func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager)
		expectedError error
	}{
		{
			name:    "Success",
			appName: "test-app",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "Empty App Name",
			appName: "",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				// No calls expected
			},
			expectedError: domain.ErrAppNameIsEmpty,
		},
		{
			name:    "App Already Exists",
			appName: "existing-app",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(storage.ErrAppAlreadyExists)
			},
			expectedError: domain.ErrAppAlreadyExists,
		},
		{
			name:    "Failed to Register App",
			appName: "failed-app",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToRegisterApp,
		},
		{
			name:    "Failed to Generate Private Key",
			appName: "key-failed-app",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Return(errors.New("key generation error"))

				// Expect DeleteApp to be called for rollback
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(nil)
			},
			expectedError: domain.ErrFailedToGenerateAndSavePrivateKey,
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
func TestDeleteApp(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		appID         string
		secretHash    string
		mockBehavior  func(storageMock *mocks.Storage)
		expectedError error
	}{
		{
			name:       "Success",
			appID:      "test-app-id",
			secretHash: "test-secret-hash",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.MatchedBy(func(data entity.AppData) bool {
					return data.ID == "test-app-id" && data.Secret == "test-secret-hash"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:       "App Not Found",
			appID:      "non-existent-app",
			secretHash: "test-secret-hash",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
					Return(storage.ErrAppNotFound)
			},
			expectedError: domain.ErrAppNotFound,
		},
		{
			name:       "Delete Failed",
			appID:      "failed-delete-app",
			secretHash: "test-secret-hash",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteApp(ctx, mock.AnythingOfType("entity.AppData")).
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

			err := app.DeleteApp(ctx, tt.appID, tt.secretHash)

			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}
