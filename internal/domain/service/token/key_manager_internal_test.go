package token

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKeyPEM(t *testing.T) {
	privateKeyPEM, err := generatePrivateKeyPEM()
	require.NoError(t, err)

	// Check if the generated PEM starts and ends with the correct headers
	expectedHeader := "-----BEGIN RSA PRIVATE KEY-----"
	expectedFooter := "-----END RSA PRIVATE KEY-----"
	privateKeyPEMString := string(privateKeyPEM)
	require.True(t, strings.HasPrefix(privateKeyPEMString, expectedHeader))
	require.True(t, strings.HasSuffix(privateKeyPEMString, expectedFooter+"\n"))

	// Extract the base64 part and decode it
	base64Data := privateKeyPEMString[len(expectedHeader)+1 : len(privateKeyPEMString)-len(expectedFooter)-1]
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64Data)
	require.NoError(t, err)

	// Parse the DER encoded private key
	_, err = x509.ParsePKCS1PrivateKey(privateKeyBytes)
	require.NoError(t, err)
}
