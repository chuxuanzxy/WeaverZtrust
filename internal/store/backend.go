package store

import "ztrust/internal/model"

type Backend interface {
	BootstrapAdmin(username, password string) error
	BootstrapApp(name, domain, backend string) error
	Authenticate(username, password, sourceIP string) (model.User, string, error)
	Logout(token string)
	UserBySession(token string) (model.User, bool)
	CheckAccess(token, host string) (model.User, model.App, error)

	CreateUser(username, displayName, password string, isAdmin bool) (model.User, error)
	UpdateUser(id int64, displayName, status string, isAdmin bool, password string) (model.User, error)
	DeleteUser(id int64) error
	ListUsers() []model.User

	CreateGroup(group model.Group) (model.Group, error)
	UpdateGroup(group model.Group) (model.Group, error)
	DeleteGroup(id int64) error
	ListGroups() []model.Group

	CreateApp(app model.App) (model.App, error)
	UpdateApp(app model.App) (model.App, error)
	DeleteApp(id int64) error
	ListApps() []model.App

	CreatePolicy(policy model.Policy) (model.Policy, error)
	DeletePolicy(id int64) error
	ListPolicies() []model.Policy

	CreateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error)
	UpdateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error)
	DeleteBodyAuditRule(id int64) error
	ListBodyAuditRules() []model.BodyAuditRule

	AddAccessLog(log model.AccessLog) model.AccessLog
	AddAdminLog(log model.AdminLog) model.AdminLog
	ListAccessLogs(filter AccessLogFilter) []model.AccessLog
	GetAccessLog(id int64) (model.AccessLog, error)
	ListLoginLogs(limit int) []model.LoginLog
	ListAdminLogs(limit int) []model.AdminLog
}
