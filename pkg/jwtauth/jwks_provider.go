package jwtauth

import (
	"context"
	"fmt"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	JWKSProvider interface {
		GetJWKS(ctx context.Context, appID string) ([]JWK, error)
	}

	JWKSService interface {
		GetJWKS(ctx context.Context, appID string) ([]JWK, error)
	}
)

type LocalJWKSProvider struct {
	JWKSService JWKSService
}

func NewLocalJWKSProvider(jwksService JWKSService) *LocalJWKSProvider {
	return &LocalJWKSProvider{
		JWKSService: jwksService,
	}
}

func (p *LocalJWKSProvider) GetJWKS(ctx context.Context, appID string) ([]JWK, error) {
	return p.JWKSService.GetJWKS(ctx, appID)
}

type RemoteJWKSProvider struct {
	client ssov1.AuthClient
	conn   *grpc.ClientConn
}

func NewRemoteJWKSProvider(target string, opts ...grpc.DialOption) (*RemoteJWKSProvider, error) {
	if len(opts) == 0 {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial jwks service: %w", err)
	}

	client := ssov1.NewAuthClient(conn)

	return &RemoteJWKSProvider{
		client: client,
		conn:   conn,
	}, nil
}

func (p *RemoteJWKSProvider) GetJWKS(ctx context.Context, appID string) ([]JWK, error) {
	resp, err := p.client.GetJWKS(ctx, &ssov1.GetJWKSRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get jwks: %w", err)
	}

	jwks := make([]JWK, 0, len(resp.Jwks))
	for _, jwk := range resp.Jwks {
		jwks = append(jwks, JWK{
			Alg: jwk.Alg,
			Kty: jwk.Kty,
			Use: jwk.Use,
			Kid: jwk.Kid,
			N:   jwk.N,
			E:   jwk.E,
		})
	}

	return jwks, nil
}

func (p *RemoteJWKSProvider) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}
