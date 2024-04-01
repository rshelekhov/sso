package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
)

const (
	issuer            = "sso.rshelekhov.com"
	emptyAppID        = int32(0)
	appID             = int32(1)
	passDefaultLength = 10
)

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLength)
}
