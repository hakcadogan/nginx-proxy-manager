package auth

import "github.com/nginx-proxy-waf/api/internal/models"

// Permission codes enforced by middleware (REQ-AUTH-003, REQ-AUTH-004).
type Permission string

const (
	PermHostsRead   Permission = "hosts:read"
	PermHostsWrite  Permission = "hosts:write"
	PermConfigRead  Permission = "config:read"
	PermConfigWrite Permission = "config:write"
	PermAuditRead   Permission = "audit:read"
	PermUsersWrite  Permission = "users:write"
	PermRateRead    Permission = "rate:read"
	PermRateWrite   Permission = "rate:write"
)

var rolePermissions = map[models.Role]map[Permission]bool{
	models.RoleAdmin: {
		PermHostsRead: true, PermHostsWrite: true,
		PermConfigRead: true, PermConfigWrite: true,
		PermAuditRead: true, PermUsersWrite: true,
		PermRateRead: true, PermRateWrite: true,
	},
	models.RoleOperator: {
		PermHostsRead: true, PermHostsWrite: true,
		PermConfigRead: true, PermConfigWrite: true,
		PermAuditRead: true,
		PermRateRead: true, PermRateWrite: true,
	},
	models.RoleViewer: {
		PermHostsRead: true,
		PermConfigRead: true,
		PermAuditRead: true,
		PermRateRead: true,
	},
}

func HasPermission(role models.Role, perm Permission) bool {
	m, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return m[perm]
}
