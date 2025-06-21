package config

// GRPCMethodSettings represents the configuration for a gRPC method
type GRPCMethodSettings struct {
	FullMethod      string // Full path of the method (e.g. "/auth.Auth/GetUserByID")
	RequireJWT      bool   // Requires a JWT authentication
	RequireClientID bool   // Requires an AppID
	SkipUserID      bool   // Skip userID check (for unauthenticated methods)
}

type GRPCMethodsConfig struct {
	settings map[string]GRPCMethodSettings
}

func NewGRPCMethodsConfig() *GRPCMethodsConfig {
	return &GRPCMethodsConfig{
		settings: initGRPCMethodSettings(),
	}
}

func (mc *GRPCMethodsConfig) GetMethodConfigs() map[string]GRPCMethodSettings {
	return mc.settings
}

func (mc *GRPCMethodsConfig) GetJWTRequiredMethods() []string {
	var methods []string

	for method, config := range mc.settings {
		if config.RequireJWT {
			methods = append(methods, method)
		}
	}

	return methods
}

func (mc *GRPCMethodsConfig) GetAppIDRequiredMethods() []string {
	var methods []string

	for method, config := range mc.settings {
		if config.RequireClientID {
			methods = append(methods, method)
		}
	}

	return methods
}

// initGRPCMethodSettings creates the initial configuration for methods
func initGRPCMethodSettings() map[string]GRPCMethodSettings {
	configs := map[string]GRPCMethodSettings{
		// Auth methods
		"/api.auth.v1.AuthService/RegisterUser": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/Login": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/VerifyEmail": {
			RequireJWT:      false,
			RequireClientID: false,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/ResetPassword": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/ChangePassword": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/GetJWKS": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},
		"/api.auth.v1.AuthService/RefreshTokens": {
			RequireJWT:      false,
			RequireClientID: true,
			SkipUserID:      true,
		},

		// User methods
		"/api.user.v1.UserService/GetUser": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},
		"/api.user.v1.UserService/UpdateUser": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},
		"/api.user.v1.UserService/DeleteUser": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},
		"/api.auth.v1.AuthService/Logout": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},

		// Admin methods
		"/api.user.v1.UserService/GetUserByID": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},
		"/api.user.v1.UserService/DeleteUserByID": {
			RequireJWT:      true,
			RequireClientID: true,
			SkipUserID:      false,
		},

		// Client methods
		"/api.client.v1.ClientManagementService/RegisterClient": {
			RequireJWT:      false,
			RequireClientID: false,
			SkipUserID:      true,
		},
	}

	for method, config := range configs {
		config.FullMethod = method
		configs[method] = config
	}

	return configs
}
