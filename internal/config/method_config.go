package config

import (
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
)

// GRPCMethodSettings represents the configuration for a gRPC method
type GRPCMethodSettings struct {
	FullMethod   string          // Full path of the method (e.g. "/auth.Auth/GetUserByID")
	RequireJWT   bool            // Requires a JWT authentication
	RequireAppID bool            // Requires an AppID
	Permission   rbac.Permission // Required permission for RBAC
	SkipUserID   bool            // Skip userID check (for unauthenticated methods)
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
		if config.RequireAppID {
			methods = append(methods, method)
		}
	}

	return methods
}

func (mc *GRPCMethodsConfig) GetRBACMethodPermissions() []rbac.MethodPermission {
	var permissions []rbac.MethodPermission

	for _, config := range mc.settings {
		permissions = append(permissions, rbac.MethodPermission{
			FullMethod: config.FullMethod,
			Permission: config.Permission,
			SkipUserID: config.SkipUserID,
		})
	}

	return permissions
}

// initGRPCMethodSettings creates the initial configuration for methods
func initGRPCMethodSettings() map[string]GRPCMethodSettings {
	configs := map[string]GRPCMethodSettings{
		// Auth methods
		"/auth.Auth/RegisterUser": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/Login": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/VerifyEmail": {
			RequireJWT:   false,
			RequireAppID: false,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/ResetPassword": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/ChangePassword": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/RegisterApp": {
			RequireJWT:   false,
			RequireAppID: false,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/GetJWKS": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},
		"/auth.Auth/Refresh": {
			RequireJWT:   false,
			RequireAppID: true,
			Permission:   rbac.Permission(""),
			SkipUserID:   true,
		},

		// User methods
		"/auth.Auth/GetUser": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionReadProfile,
			SkipUserID:   false,
		},
		"/auth.Auth/UpdateUser": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionUpdateProfile,
			SkipUserID:   false,
		},
		"/auth.Auth/DeleteUser": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionDeleteProfile,
			SkipUserID:   false,
		},
		"/auth.Auth/Logout": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionReadProfile,
			SkipUserID:   false,
		},

		// Admin methods
		"/auth.Auth/GetUserByID": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionReadAnyProfile,
			SkipUserID:   false,
		},
		"/auth.Auth/DeleteUserByID": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionDeleteAny,
			SkipUserID:   false,
		},
		"/auth.Auth/ChangeUserRole": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionManageRoles,
			SkipUserID:   false,
		},
		"/auth.Auth/GetUserRole": {
			RequireJWT:   true,
			RequireAppID: true,
			Permission:   rbac.PermissionReadAnyProfile,
			SkipUserID:   false,
		},
	}

	for method, config := range configs {
		config.FullMethod = method
		configs[method] = config
	}

	return configs
}
