package api_tests

import (
	"log"
	"testing"

	"github.com/cristalhq/aconfig"
	"github.com/cristalhq/aconfig/aconfigdotenv"
	"github.com/cristalhq/aconfig/aconfigyaml"
)

type Config struct {
	Issuer                   string `yaml:"test_issuer"`
	ClientID                 string `yaml:"test_client_id"`
	VerificationURL          string `yaml:"test_verification_url"`
	ConfirmChangePasswordURL string `yaml:"test_confirm_change_password_url"`
}

func TestMain(m *testing.M) {
	MustLoadPath(localTestsConfigPath)
	m.Run()
}

var cfg = Config{}

const localTestsConfigPath = "../config/local_tests.yaml"

func MustLoadPath(configPath string) *Config {
	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		Files:              []string{configPath},
		AllowUnknownFields: true,
		SkipFlags:          true,
		FileDecoders: map[string]aconfig.FileDecoder{
			".yaml": aconfigyaml.New(),
			".yml":  aconfigyaml.New(),
			".env":  aconfigdotenv.New(),
		},
	})

	err := loader.Load()
	if err != nil {
		log.Fatalf("error loading config file %s: %s", configPath, err)
	}

	return &cfg
}
