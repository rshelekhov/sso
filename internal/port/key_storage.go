package port

type KeyStorage interface {
	SavePrivateKey(appID string, privateKeyPEM []byte) error
	GetPrivateKey(appID string) ([]byte, error)
}
