package config

// GRPCMethodSettings represents the configuration for a gRPC method
type GRPCMethodSettings struct {
	FullMethod   string // Full path of the method (e.g. "/auth.Auth/GetUserByID")
	RequireJWT   bool   // Requires a JWT authentication
	RequireClientID bool   // Requires an AppID
	SkipUserID   bool   // Skip userID check (for unauthenticated methods)
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
		"/auth.Auth/RegisterUser": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},
		"/auth.Auth/Login": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},
		"/auth.Auth/VerifyEmail": {
			RequireJWT:   false,
			RequireClientID: false,
			SkipUserID:   true,
		},
		"/auth.Auth/ResetPassword": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},
		"/auth.Auth/ChangePassword": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},
		"/auth.Auth/RegisterApp": {
			RequireJWT:   false,
			RequireClientID: false,
			SkipUserID:   true,
		},
		"/auth.Auth/GetJWKS": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},
		"/auth.Auth/Refresh": {
			RequireJWT:   false,
			RequireClientID: true,
			SkipUserID:   true,
		},

		// User methods
		"/auth.Auth/GetUser": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/UpdateUser": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/DeleteUser": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/Logout": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},

		// Admin methods
		"/auth.Auth/GetUserByID": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/DeleteUserByID": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/ChangeUserRole": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
		"/auth.Auth/GetUserRole": {
			RequireJWT:   true,
			RequireClientID: true,
			SkipUserID:   false,
		},
	}

	for method, config := range configs {
		config.FullMethod = method
		configs[method] = config
	}

	return configs
}
