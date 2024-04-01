package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

const (
	issuer     = "sso.rshelekhov.com"
	emptyAppID = 0
	appID      = 1
)

func TestLoginHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetTokenData())

	token := respLogin.GetTokenData()
	require.NotEmpty(t, token)

	jwks, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppId: appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, jwks.GetJwks())

	jwk, err := getJWKByKid(jwks.GetJwks(), token.GetKid())
	require.NoError(t, err)
	require.NotEmpty(t, jwk)

	n, err := base64.RawURLEncoding.DecodeString(jwk.GetN())
	require.NoError(t, err)

	e, err := base64.RawURLEncoding.DecodeString(jwk.GetE())
	require.NoError(t, err)

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}

	loginTime := time.Now()

	// Parse the token using the public key
	tokenParsed, err := jwt.Parse(token.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokenParsed)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, issuer, claims[key.Issuer].(string))
	assert.Equal(t, email, claims[key.Email].(string))
	assert.Equal(t, appID, int(claims[key.AppID].(float64)))

	const deltaSeconds = 1

	// check if exp of token is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, float64(loginTime.Add(st.Cfg.JWTAuth.AccessTokenTTL).Unix()), claims[key.ExpirationAt].(float64), deltaSeconds)
}

func getJWKByKid(jwks []*ssov1.JWK, kid string) (*ssov1.JWK, error) {
	for _, jwk := range jwks {
		if jwk.GetKid() == kid {
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("JWK with kid %s not found", kid)
}
