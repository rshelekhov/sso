package token

import "context"

type MetricsRecorder interface {
	// Token issuance
	RecordAccessTokenIssued(ctx context.Context, clientID string)
	RecordRefreshTokenIssued(ctx context.Context, clientID string)
	RecordAccessTokenIssueFailed(ctx context.Context, clientID string)

	// Token revocation
	RecordTokenRevokedExpired(ctx context.Context, clientID string)
	RecordTokenRevokedSecurity(ctx context.Context, clientID string)
	RecordTokenValidationDuration(ctx context.Context, clientID string, duration float64)

	// Key generation duration
	RecordPrivateKeyPEMGenerationDuration(ctx context.Context, clientID string, duration float64)
}
