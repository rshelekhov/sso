package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	"testing"
)

const passDefaultLength = 10

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLength)
}

func Test(t *testing.T) {

}
