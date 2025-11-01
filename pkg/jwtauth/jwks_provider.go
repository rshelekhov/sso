package jwtauth

import (
	"context"
	"fmt"

	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type (
	JWKSProvider interface {
		GetJWKS(ctx context.Context, clientID string) ([]JWK, error)
	}

	JWKSService interface {
		GetJWKS(ctx context.Context, clientID string) ([]JWK, error)
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

func (p *LocalJWKSProvider) GetJWKS(ctx context.Context, clientID string) ([]JWK, error) {
	return p.JWKSService.GetJWKS(ctx, clientID)
}

type RemoteJWKSProvider struct {
	client authv1.AuthServiceClient
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

	client := authv1.NewAuthServiceClient(conn)

	return &RemoteJWKSProvider{
		client: client,
		conn:   conn,
	}, nil
}

func (p *RemoteJWKSProvider) GetJWKS(ctx context.Context, clientID string) ([]JWK, error) {
	// Add clientID to gRPC metadata for the SSO service
	md := metadata.Pairs("x-client-id", clientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := p.client.GetJWKS(ctx, &authv1.GetJWKSRequest{})
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
