package rbac

type Role string

const (
	// RoleAdmin can do anything
	RoleAdmin Role = "admin"

	// RoleUser can only do actions with their own account
	RoleUser Role = "user"
)

func (r Role) String() string {
	return string(r)
}

type Permission string

const (
	// Profile permissions
	PermissionReadProfile   Permission = "read:profile"
	PermissionUpdateProfile Permission = "update:profile"
	PermissionDeleteProfile Permission = "delete:profile"

	// Admin permissions
	PermissionReadAnyProfile Permission = "read:any_profile"
	PermissionDeleteAny      Permission = "delete:any"
	PermissionManageRoles    Permission = "manage:roles"
)

// RolePermissions maps roles to permissions
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermissionReadAnyProfile,
		PermissionDeleteAny,
		PermissionManageRoles,
		// Admin also has all profile permissions
		PermissionReadProfile,
		PermissionUpdateProfile,
		PermissionDeleteProfile,
	},
	RoleUser: {
		PermissionReadProfile,
		PermissionUpdateProfile,
		PermissionDeleteProfile,
	},
}

// MethodPermission defines required permissions for a gRPC method
type MethodPermission struct {
	FullMethod string
	Permission Permission
	SkipUserID bool
}
