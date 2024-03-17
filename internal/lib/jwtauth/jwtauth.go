package jwtauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
)

type TokenService struct {
	SignKey                  string
	SigningMethod            jwt.SigningMethod
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
	PasswordHashCost         int
	PasswordHashSalt         string
}

func NewJWTokenService(
	signKey string,
	signingMethod jwt.SigningMethod,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenCookieDomain string,
	refreshTokenCookiePath string,
	passwordHashCost int,
	passwordHashSalt string,
) *TokenService {
	return &TokenService{
		SignKey:                  signKey,
		SigningMethod:            signingMethod,
		AccessTokenTTL:           accessTokenTTL,
		RefreshTokenTTL:          refreshTokenTTL,
		RefreshTokenCookieDomain: refreshTokenCookieDomain,
		RefreshTokenCookiePath:   refreshTokenCookiePath,
		PasswordHashCost:         passwordHashCost,
		PasswordHashSalt:         passwordHashSalt,
	}
}

type TokenData struct {
	AccessToken      string
	RefreshToken     string
	Domain           string
	Path             string
	ExpiresAt        time.Time
	HTTPOnly         bool
	AdditionalFields map[string]string
}

func (j *TokenService) NewAccessToken(additionalClaims map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(j.AccessTokenTTL).Unix(),
	}

	if additionalClaims != nil { // nolint:gosimple
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(j.SigningMethod, claims)

	return token.SignedString([]byte(j.SignKey))
}

func (j *TokenService) NewRefreshToken() (string, error) {
	token := ksuid.New().String()
	return token, nil
}

func SetTokenCookie(w http.ResponseWriter, name, value, domain, path string, expiresAt time.Time, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expiresAt,
		HttpOnly: httpOnly,
	})
}

func SetRefreshTokenCookie(w http.ResponseWriter, refreshToken, domain, path string, expiresAt time.Time, httpOnly bool) {
	SetTokenCookie(w, "refreshToken", refreshToken, domain, path, expiresAt, httpOnly)
}

func SendTokensToWeb(w http.ResponseWriter, data TokenData, httpStatus int) {
	SetRefreshTokenCookie(w, data.RefreshToken, data.Domain, data.Path, data.ExpiresAt, data.HTTPOnly)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{"accessToken": data.AccessToken}

	if len(data.AdditionalFields) > 0 {
		for key, value := range data.AdditionalFields {
			responseBody[key] = value
		}
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		return
	}
}

func SendTokensToMobileApp(w http.ResponseWriter, data TokenData, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{"accessToken": data.AccessToken, "refreshToken": data.RefreshToken}

	if len(data.AdditionalFields) > 0 {
		for key, value := range data.AdditionalFields {
			responseBody[key] = value
		}
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		return
	}
}
