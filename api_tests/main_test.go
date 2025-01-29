package api_tests

import (
	"log"
	"testing"

	"github.com/spf13/viper"
)

type Config struct {
	Issuer                   string `mapstructure:"TEST_ISSUER" envDefault:"sso.reframedapp.com"`
	AppID                    string `mapstructure:"TEST_APP_ID" envDefault:"test-app-id"`
	VerificationURL          string `mapstructure:"TEST_VERIFICATION_URL" envDefault:"reframedapp.com/confirm?token="`
	ConfirmChangePasswordURL string `mapstructure:"TEST_CONFIRM_CHANGE_PASSWORD_URL" envDefault:"reframedapp.com/password/change?token="`

	// Test user data for testing Mailgun email session
	User1Email     string `mapstructure:"TEST_USER_1_EMAIL" envDefault:"test-user-1@reframedapp.com"`
	User1Password  string `mapstructure:"TEST_USER_1_PASSWORD" envDefault:"password"`
	User1UserAgent string `mapstructure:"TEST_USER_1_USER_AGENT" envDefault:"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_1) AppleWebKit/5340 (KHTML, like Gecko) Chrome/39.0.825.0 Mobile Safari/5340"`
	User1IP        string `mapstructure:"TEST_USER_1_IP" envDefault:"17.180.103.17"`

	// Test user data for testing Mailgun email session
	User2Email     string `mapstructure:"TEST_USER_2_EMAIL" envDefault:"test-user-2@reframedapp.com"`
	User2Password  string `mapstructure:"TEST_USER_2_PASSWORD" envDefault:"password"`
	User2UserAgent string `mapstructure:"TEST_USER_2_USER_AGENT" envDefault:"Opera/9.43 (X11; Linux i686; en-US) Presto/2.9.217 Version/12.00"`
	User2IP        string `mapstructure:"TEST_USER_2_IP" envDefault:"166.43.148.97"`
}

func TestMain(m *testing.M) {
	MustLoadPath(localTestsConfigPath)
	m.Run()
}

var cfg = Config{}

const localTestsConfigPath = "../config/local_tests.env"

func MustLoadPath(configPath string) *Config {
	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("error finding or reading config file: %s", err)
	}

	viper.AutomaticEnv()

	err = viper.Unmarshal(&cfg)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct: %s: ", err)
	}

	return &cfg
}
