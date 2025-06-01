package api_tests

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
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

type adminUser struct {
	email       string
	password    string
	accessToken string
	userID      string
}

func registerAndLoginAdmin(t *testing.T, st *suite.Suite, ctx context.Context) (*adminUser, func()) {
	// Register admin user via CLI
	adminEmail := gofakeit.Email()
	adminPass := randomFakePassword()

	err := registerAdmin(t, cfg.AppID, adminEmail, adminPass)
	require.NoError(t, err)

	// Login as admin
	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    adminEmail,
		Password: adminPass,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetTokenData())

	admin := &adminUser{
		email:       adminEmail,
		password:    adminPass,
		accessToken: respLogin.GetTokenData().GetAccessToken(),
	}

	// Get admin's ID
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	respUser, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)

	admin.userID = respUser.GetUser().GetId()

	cleanup := func() {
		md = metadata.Pairs(appid.Header, cfg.AppID)
		md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
		cleanCtx := metadata.NewOutgoingContext(ctx, md)

		_, err = st.AuthClient.DeleteUser(cleanCtx, &ssov1.DeleteUserRequest{})
		require.NoError(t, err)
	}

	return admin, cleanup
}

func registerAdmin(t *testing.T, appID, email, password string) error {
	cliPath := "../cmd/register_admin/main.go"
	if _, err := os.Stat(cliPath); os.IsNotExist(err) {
		return fmt.Errorf("register_admin CLI not found at %s", cliPath)
	}

	cmd := exec.Command("go", "run", cliPath,
		"-app-id", appID,
		"-email", email,
		"-password", password)

	cmd.Env = append(os.Environ(), "CONFIG_PATH=../config/.env")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to register admin: %s", output)
		return fmt.Errorf("failed to register admin: %w", err)
	}

	return nil
}
