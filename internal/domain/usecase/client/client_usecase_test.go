package client

import (
	"context"
	"errors"
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/client/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/logger/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestClientUsecase_RegisterClient(t *testing.T) {
	ctx := context.Background()

	clientName := "test-client"

	tests := []struct {
		name          string
		clientName    string
		mockBehavior  func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager)
		expectedError error
	}{
		{
			name:       "Success",
			clientName: clientName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name:       "Empty client name",
			clientName: "",
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				// No calls expected
			},
			expectedError: domain.ErrClientNameIsEmpty,
		},
		{
			name:       "Client already exists",
			clientName: clientName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(storage.ErrClientAlreadyExists)
			},
			expectedError: domain.ErrClientAlreadyExists,
		},
		{
			name:       "Failed to register client",
			clientName: clientName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToRegisterClient,
		},
		{
			name:       "Failed to generate private key",
			clientName: clientName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(errors.New("key generation error"))

				// Expect DeleteClient to be called for rollback
				storageMock.EXPECT().DeleteClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(nil)
			},
			expectedError: domain.ErrFailedToGenerateAndSavePrivateKey,
		},
		{
			name:       "Failed to delete client",
			clientName: clientName,
			mockBehavior: func(storageMock *mocks.Storage, keyManagerMock *mocks.KeyManager) {
				storageMock.EXPECT().RegisterClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(nil)

				keyManagerMock.EXPECT().GenerateAndSavePrivateKey(mock.AnythingOfType("string")).
					Once().
					Return(errors.New("key generation error"))

				// Expect DeleteClient to be called for rollback
				storageMock.EXPECT().DeleteClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(domain.ErrFailedToDeleteClient)
			},
			expectedError: domain.ErrFailedToDeleteClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := mocks.NewStorage(t)
			keyManagerMock := mocks.NewKeyManager(t)

			tt.mockBehavior(storageMock, keyManagerMock)

			log := slogdiscard.NewDiscardLogger()

			app := NewUsecase(log, keyManagerMock, storageMock)

			err := app.RegisterClient(ctx, tt.clientName)

			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}

func TestClientUsecase_DeleteClient(t *testing.T) {
	ctx := context.Background()

	clientID := "test-client-id"
	secretHash := "test-secret-hash"

	tests := []struct {
		name          string
		mockBehavior  func(storageMock *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteClient(ctx, mock.MatchedBy(func(data entity.ClientData) bool {
					return data.ID == clientID && data.Secret == secretHash
				})).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Client not found",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(storage.ErrClientNotFound)
			},
			expectedError: domain.ErrClientNotFound,
		},
		{
			name: "Delete failed",
			mockBehavior: func(storageMock *mocks.Storage) {
				storageMock.EXPECT().DeleteClient(ctx, mock.AnythingOfType("entity.ClientData")).
					Once().
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToDeleteClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := mocks.NewStorage(t)

			tt.mockBehavior(storageMock)

			log := slogdiscard.NewDiscardLogger()

			app := NewUsecase(log, nil, storageMock)

			err := app.DeleteClient(ctx, clientID, secretHash)

			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}
