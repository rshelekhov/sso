package rbac

import "golang.org/x/exp/slices"

// HasPermission checks if a role has a specific permission
func HasPermission(role Role, permission Permission) bool {
	// Empty permission means the method is accessible to everyone
	if permission == "" {
		return true
	}

	permissions, exists := RolePermissions[role]
	if !exists {
		return false
	}

	return slices.Contains(permissions, permission)
}

// IsValidRole checks if a role is valid
func IsValidRole(role Role) bool {
	_, exists := RolePermissions[role]
	return exists
}
