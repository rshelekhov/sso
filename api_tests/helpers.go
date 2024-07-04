package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
)

const (
	issuer            = "sso.rshelekhov.com"
	emptyAppID        = ""
	appID             = "test-app-id"
	passDefaultLength = 10
)

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLength)
}
