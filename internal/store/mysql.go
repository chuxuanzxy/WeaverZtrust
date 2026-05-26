package store

import (
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"ztrust/internal/audit"
	"ztrust/internal/auth"
	"ztrust/internal/model"
)

type MySQLStore struct {
	db         *sql.DB
	sessionTTL time.Duration
}

func NewMySQLStore(dsn string, sessionTTL time.Duration) (*MySQLStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("mysql dsn is required")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &MySQLStore{db: db, sessionTTL: sessionTTL}, nil
}

func (s *MySQLStore) Close() error {
	return s.db.Close()
}

func (s *MySQLStore) BootstrapAdmin(username, password string) error {
	_, err := s.userByUsername(username)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now()
	_, err = s.db.Exec(`
		INSERT INTO users (username, display_name, password_hash, status, is_admin, created_at, updated_at)
		VALUES (?, ?, ?, 'active', TRUE, ?, ?)`,
		username, "System Admin", hash, now, now,
	)
	return err
}

func (s *MySQLStore) BootstrapApp(name, domain, backend string) error {
	_, err := s.CreateApp(model.App{Name: name, Domain: domain, BackendURL: backend, Enabled: true, ProxyTimeoutMS: 30000})
	if errors.Is(err, ErrAlreadyExists) {
		return nil
	}
	return err
}

func (s *MySQLStore) Authenticate(username, password, sourceIP string) (model.User, string, error) {
	user, err := s.userByUsername(username)
	if err != nil || user.Status != "active" || !auth.VerifyPassword(user.PasswordHash, password) {
		s.addLoginLog(username, sourceIP, "failure", "invalid_credentials")
		return model.User{}, "", ErrUnauthorized
	}
	token, err := randomToken()
	if err != nil {
		return model.User{}, "", err
	}
	now := time.Now()
	expiresAt := now.Add(s.sessionTTL)
	tx, err := s.db.Begin()
	if err != nil {
		return model.User{}, "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`, now, now, user.ID); err != nil {
		return model.User{}, "", err
	}
	if _, err := tx.Exec(`INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`, token, user.ID, expiresAt, now); err != nil {
		return model.User{}, "", err
	}
	if _, err := tx.Exec(`INSERT INTO login_logs (username, source_ip, result, failure_reason, created_at) VALUES (?, ?, 'success', NULL, ?)`, username, sourceIP, now); err != nil {
		return model.User{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, "", err
	}
	user.LastLoginAt = &now
	user.UpdatedAt = now
	return user, token, nil
}

func (s *MySQLStore) Logout(token string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

func (s *MySQLStore) UserBySession(token string) (model.User, bool) {
	row := s.db.QueryRow(`
		SELECT u.id, u.username, u.display_name, u.password_hash, u.status, u.is_admin, u.last_login_at, u.created_at, u.updated_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = ? AND s.expires_at > ?`,
		token, time.Now(),
	)
	user, err := scanUser(row)
	if err != nil || user.Status != "active" {
		return model.User{}, false
	}
	return user, true
}

func (s *MySQLStore) CheckAccess(token, host string) (model.User, model.App, error) {
	user, ok := s.UserBySession(token)
	if !ok {
		return model.User{}, model.App{}, ErrUnauthorized
	}
	app, err := s.appByDomain(host)
	if err != nil {
		return user, model.App{}, err
	}
	if !app.Enabled {
		return user, app, ErrForbidden
	}
	if user.IsAdmin || s.allowed(user.ID, app.ID) {
		return user, app, nil
	}
	return user, app, ErrForbidden
}

func (s *MySQLStore) CreateUser(username, displayName, password string, isAdmin bool) (model.User, error) {
	if _, err := s.userByUsername(username); err == nil {
		return model.User{}, ErrAlreadyExists
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	now := time.Now()
	res, err := s.db.Exec(`
		INSERT INTO users (username, display_name, password_hash, status, is_admin, created_at, updated_at)
		VALUES (?, ?, ?, 'active', ?, ?, ?)`,
		username, displayName, hash, isAdmin, now, now,
	)
	if err != nil {
		return model.User{}, err
	}
	id, _ := res.LastInsertId()
	return s.userByID(id)
}

func (s *MySQLStore) UpdateUser(id int64, displayName, status string, isAdmin bool, password string) (model.User, error) {
	user, err := s.userByID(id)
	if err != nil {
		return model.User{}, err
	}
	if displayName != "" {
		user.DisplayName = displayName
	}
	if status != "" {
		user.Status = status
	}
	user.IsAdmin = isAdmin
	if password != "" {
		hash, err := auth.HashPassword(password)
		if err != nil {
			return model.User{}, err
		}
		user.PasswordHash = hash
	}
	user.UpdatedAt = time.Now()
	_, err = s.db.Exec(`
		UPDATE users SET display_name = ?, password_hash = ?, status = ?, is_admin = ?, updated_at = ? WHERE id = ?`,
		user.DisplayName, user.PasswordHash, user.Status, user.IsAdmin, user.UpdatedAt, user.ID,
	)
	if err != nil {
		return model.User{}, err
	}
	return user, nil
}

func (s *MySQLStore) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrNotFound
	}
	_, _ = s.db.Exec(`DELETE FROM user_group_members WHERE user_id = ?`, id)
	_, _ = s.db.Exec(`DELETE FROM policies WHERE subject = 'user' AND subject_id = ?`, id)
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	return nil
}

func (s *MySQLStore) ListUsers() []model.User {
	rows, err := s.db.Query(`
		SELECT id, username, display_name, password_hash, status, is_admin, last_login_at, created_at, updated_at
		FROM users ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		user, err := scanUser(rows)
		if err == nil {
			out = append(out, user)
		}
	}
	return out
}

func (s *MySQLStore) CreateGroup(group model.Group) (model.Group, error) {
	now := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return model.Group{}, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO user_groups (name, created_at, updated_at) VALUES (?, ?, ?)`, group.Name, now, now)
	if err != nil {
		return model.Group{}, err
	}
	id, _ := res.LastInsertId()
	if err := replaceGroupMembers(tx, id, group.UserIDs, now); err != nil {
		return model.Group{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Group{}, err
	}
	group.ID = id
	group.CreatedAt = now
	group.UpdatedAt = now
	return group, nil
}

func (s *MySQLStore) UpdateGroup(group model.Group) (model.Group, error) {
	now := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return model.Group{}, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE user_groups SET name = ?, updated_at = ? WHERE id = ?`, group.Name, now, group.ID)
	if err != nil {
		return model.Group{}, err
	}
	if rowsAffected(res) == 0 {
		return model.Group{}, ErrNotFound
	}
	if err := replaceGroupMembers(tx, group.ID, group.UserIDs, now); err != nil {
		return model.Group{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Group{}, err
	}
	return s.groupByID(group.ID)
}

func (s *MySQLStore) DeleteGroup(id int64) error {
	res, err := s.db.Exec(`DELETE FROM user_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrNotFound
	}
	_, _ = s.db.Exec(`DELETE FROM user_group_members WHERE group_id = ?`, id)
	_, _ = s.db.Exec(`DELETE FROM policies WHERE subject = 'group' AND subject_id = ?`, id)
	return nil
}

func (s *MySQLStore) ListGroups() []model.Group {
	rows, err := s.db.Query(`SELECT id, name, created_at, updated_at FROM user_groups ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.Group{}
	for rows.Next() {
		var group model.Group
		if err := rows.Scan(&group.ID, &group.Name, &group.CreatedAt, &group.UpdatedAt); err == nil {
			group.UserIDs = s.groupMemberIDs(group.ID)
			out = append(out, group)
		}
	}
	return out
}

func (s *MySQLStore) CreateApp(app model.App) (model.App, error) {
	app.Domain = normalizeHost(app.Domain)
	if _, err := s.appByDomain(app.Domain); err == nil {
		return model.App{}, ErrAlreadyExists
	}
	now := time.Now()
	if app.ProxyTimeoutMS == 0 {
		app.ProxyTimeoutMS = 30000
	}
	res, err := s.db.Exec(`
		INSERT INTO apps (name, domain, backend_url, enabled, proxy_timeout_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		app.Name, app.Domain, app.BackendURL, app.Enabled, app.ProxyTimeoutMS, now, now,
	)
	if err != nil {
		return model.App{}, err
	}
	id, _ := res.LastInsertId()
	return s.appByID(id)
}

func (s *MySQLStore) UpdateApp(app model.App) (model.App, error) {
	current, err := s.appByID(app.ID)
	if err != nil {
		return model.App{}, err
	}
	if app.Name != "" {
		current.Name = app.Name
	}
	if app.Domain != "" {
		current.Domain = normalizeHost(app.Domain)
	}
	if app.BackendURL != "" {
		current.BackendURL = app.BackendURL
	}
	if app.ProxyTimeoutMS > 0 {
		current.ProxyTimeoutMS = app.ProxyTimeoutMS
	}
	current.Enabled = app.Enabled
	current.UpdatedAt = time.Now()
	_, err = s.db.Exec(`
		UPDATE apps SET name = ?, domain = ?, backend_url = ?, enabled = ?, proxy_timeout_ms = ?, updated_at = ? WHERE id = ?`,
		current.Name, current.Domain, current.BackendURL, current.Enabled, current.ProxyTimeoutMS, current.UpdatedAt, current.ID,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.App{}, ErrAlreadyExists
		}
		return model.App{}, err
	}
	return current, nil
}

func (s *MySQLStore) DeleteApp(id int64) error {
	res, err := s.db.Exec(`DELETE FROM apps WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrNotFound
	}
	_, _ = s.db.Exec(`DELETE FROM policies WHERE app_id = ?`, id)
	_, _ = s.db.Exec(`DELETE FROM body_audit_rules WHERE app_id = ?`, id)
	return nil
}

func (s *MySQLStore) ListApps() []model.App {
	rows, err := s.db.Query(`SELECT id, name, domain, backend_url, enabled, proxy_timeout_ms, created_at, updated_at FROM apps ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.App{}
	for rows.Next() {
		app, err := scanApp(rows)
		if err == nil {
			out = append(out, app)
		}
	}
	return out
}

func (s *MySQLStore) CreatePolicy(policy model.Policy) (model.Policy, error) {
	if policy.Effect == "" {
		policy.Effect = "allow"
	}
	now := time.Now()
	res, err := s.db.Exec(`
		INSERT INTO policies (app_id, subject, subject_id, effect, not_before, not_after, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		policy.AppID, policy.Subject, policy.SubjectID, policy.Effect, nullableTime(policy.NotBefore), nullableTime(policy.NotAfter), now, now,
	)
	if err != nil {
		return model.Policy{}, err
	}
	id, _ := res.LastInsertId()
	return s.policyByID(id)
}

func (s *MySQLStore) DeletePolicy(id int64) error {
	res, err := s.db.Exec(`DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *MySQLStore) ListPolicies() []model.Policy {
	rows, err := s.db.Query(`SELECT id, app_id, subject, subject_id, effect, not_before, not_after, created_at, updated_at FROM policies ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.Policy{}
	for rows.Next() {
		policy, err := scanPolicy(rows)
		if err == nil {
			out = append(out, policy)
		}
	}
	return out
}

func (s *MySQLStore) CreateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error) {
	rule = normalizeBodyAuditRule(rule)
	now := time.Now()
	res, err := s.db.Exec(`
		INSERT INTO body_audit_rules
		(name, app_id, path_pattern, match_type, methods, status_min, status_max, capture_request, capture_response, max_body_bytes, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.Name, nullableInt64(rule.AppID), rule.PathPattern, rule.MatchType, strings.Join(rule.Methods, ","), nullableInt(rule.StatusMin), nullableInt(rule.StatusMax),
		rule.CaptureRequest, rule.CaptureResponse, rule.MaxBodyBytes, rule.Enabled, now, now,
	)
	if err != nil {
		return model.BodyAuditRule{}, err
	}
	id, _ := res.LastInsertId()
	return s.bodyAuditRuleByID(id)
}

func (s *MySQLStore) UpdateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error) {
	rule = normalizeBodyAuditRule(rule)
	now := time.Now()
	res, err := s.db.Exec(`
		UPDATE body_audit_rules
		SET name = ?, app_id = ?, path_pattern = ?, match_type = ?, methods = ?, status_min = ?, status_max = ?,
		    capture_request = ?, capture_response = ?, max_body_bytes = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		rule.Name, nullableInt64(rule.AppID), rule.PathPattern, rule.MatchType, strings.Join(rule.Methods, ","), nullableInt(rule.StatusMin), nullableInt(rule.StatusMax),
		rule.CaptureRequest, rule.CaptureResponse, rule.MaxBodyBytes, rule.Enabled, now, rule.ID,
	)
	if err != nil {
		return model.BodyAuditRule{}, err
	}
	if rowsAffected(res) == 0 {
		return model.BodyAuditRule{}, ErrNotFound
	}
	return s.bodyAuditRuleByID(rule.ID)
}

func (s *MySQLStore) DeleteBodyAuditRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM body_audit_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *MySQLStore) ListBodyAuditRules() []model.BodyAuditRule {
	rows, err := s.db.Query(`
		SELECT id, name, app_id, path_pattern, match_type, methods, status_min, status_max,
		       capture_request, capture_response, max_body_bytes, enabled, created_at, updated_at
		FROM body_audit_rules ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.BodyAuditRule{}
	for rows.Next() {
		rule, err := scanBodyAuditRule(rows)
		if err == nil {
			out = append(out, rule)
		}
	}
	return out
}

func (s *MySQLStore) AddAccessLog(log model.AccessLog) model.AccessLog {
	now := time.Now()
	log.CreatedAt = now
	if log.AppID == 0 {
		log.AppID = s.appIDForDomain(log.Domain)
	}
	s.applyBodyAuditRule(&log)
	res, err := s.db.Exec(`
		INSERT INTO access_logs
		(app_id, user_id, username, source_ip, domain, path, method, status_code, duration_ms, proxy_result, user_agent, browser, os,
		 body_rule_id, has_request_body, has_response_body, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableInt64(log.AppID), nullableInt64(log.UserID), nullEmptyString(log.Username), log.SourceIP, log.Domain, log.Path, log.Method, log.StatusCode,
		log.DurationMS, log.ProxyResult, log.UserAgent, log.Browser, log.OS, nullableInt64(log.BodyRuleID), log.HasRequestBody, log.HasResponseBody, now,
	)
	if err != nil {
		return log
	}
	log.ID, _ = res.LastInsertId()
	s.addAccessLogBody(log.ID, "request", log.RequestBody, now)
	s.addAccessLogBody(log.ID, "response", log.ResponseBody, now)
	return log
}

func (s *MySQLStore) AddAdminLog(log model.AdminLog) model.AdminLog {
	now := time.Now()
	log.CreatedAt = now
	res, err := s.db.Exec(`
		INSERT INTO admin_logs (admin_user_id, admin_username, object_type, object_id, action, before_summary, after_summary, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		log.AdminUserID, log.AdminUsername, log.ObjectType, nullableInt64(log.ObjectID), log.Action, nullEmptyString(log.BeforeSummary), nullEmptyString(log.AfterSummary), now,
	)
	if err == nil {
		log.ID, _ = res.LastInsertId()
	}
	return log
}

func (s *MySQLStore) ListAccessLogs(filter AccessLogFilter) []model.AccessLog {
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
		SELECT id, app_id, user_id, username, source_ip, domain, path, method, status_code, duration_ms, proxy_result, user_agent, browser, os,
		       body_rule_id, has_request_body, has_response_body, created_at
		FROM access_logs WHERE 1 = 1`
	args := []any{}
	if filter.Username != "" {
		query += ` AND username = ?`
		args = append(args, filter.Username)
	}
	if filter.SourceIP != "" {
		query += ` AND source_ip = ?`
		args = append(args, filter.SourceIP)
	}
	if filter.Path != "" {
		query += ` AND path LIKE ?`
		args = append(args, "%"+filter.Path+"%")
	}
	if filter.StatusCode != 0 {
		query += ` AND status_code = ?`
		args = append(args, filter.StatusCode)
	}
	if filter.From != nil {
		query += ` AND created_at >= ?`
		args = append(args, *filter.From)
	}
	if filter.To != nil {
		query += ` AND created_at <= ?`
		args = append(args, *filter.To)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.AccessLog{}
	for rows.Next() {
		log, err := scanAccessLog(rows)
		if err == nil {
			out = append(out, stripAccessLogBodies(log))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *MySQLStore) GetAccessLog(id int64) (model.AccessLog, error) {
	row := s.db.QueryRow(`
		SELECT id, app_id, user_id, username, source_ip, domain, path, method, status_code, duration_ms, proxy_result, user_agent, browser, os,
		       body_rule_id, has_request_body, has_response_body, created_at
		FROM access_logs WHERE id = ?`, id)
	log, err := scanAccessLog(row)
	if err != nil {
		return model.AccessLog{}, err
	}
	s.loadAccessLogBodies(&log)
	return log, nil
}

func (s *MySQLStore) ListLoginLogs(limit int) []model.LoginLog {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, username, source_ip, result, failure_reason, created_at FROM login_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.LoginLog{}
	for rows.Next() {
		log, err := scanLoginLog(rows)
		if err == nil {
			out = append(out, log)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *MySQLStore) ListAdminLogs(limit int) []model.AdminLog {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, admin_user_id, admin_username, object_type, object_id, action, before_summary, after_summary, created_at FROM admin_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.AdminLog{}
	for rows.Next() {
		log, err := scanAdminLog(rows)
		if err == nil {
			out = append(out, log)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *MySQLStore) userByUsername(username string) (model.User, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, password_hash, status, is_admin, last_login_at, created_at, updated_at
		FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (s *MySQLStore) userByID(id int64) (model.User, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, password_hash, status, is_admin, last_login_at, created_at, updated_at
		FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *MySQLStore) appByDomain(domain string) (model.App, error) {
	row := s.db.QueryRow(`SELECT id, name, domain, backend_url, enabled, proxy_timeout_ms, created_at, updated_at FROM apps WHERE domain = ?`, normalizeHost(domain))
	return scanApp(row)
}

func (s *MySQLStore) appByID(id int64) (model.App, error) {
	row := s.db.QueryRow(`SELECT id, name, domain, backend_url, enabled, proxy_timeout_ms, created_at, updated_at FROM apps WHERE id = ?`, id)
	return scanApp(row)
}

func (s *MySQLStore) appIDForDomain(domain string) int64 {
	app, err := s.appByDomain(domain)
	if err != nil {
		return 0
	}
	return app.ID
}

func (s *MySQLStore) groupByID(id int64) (model.Group, error) {
	row := s.db.QueryRow(`SELECT id, name, created_at, updated_at FROM user_groups WHERE id = ?`, id)
	var group model.Group
	if err := row.Scan(&group.ID, &group.Name, &group.CreatedAt, &group.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Group{}, ErrNotFound
		}
		return model.Group{}, err
	}
	group.UserIDs = s.groupMemberIDs(id)
	return group, nil
}

func (s *MySQLStore) groupMemberIDs(groupID int64) []int64 {
	rows, err := s.db.Query(`SELECT user_id FROM user_group_members WHERE group_id = ? ORDER BY user_id`, groupID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (s *MySQLStore) policyByID(id int64) (model.Policy, error) {
	row := s.db.QueryRow(`SELECT id, app_id, subject, subject_id, effect, not_before, not_after, created_at, updated_at FROM policies WHERE id = ?`, id)
	return scanPolicy(row)
}

func (s *MySQLStore) bodyAuditRuleByID(id int64) (model.BodyAuditRule, error) {
	row := s.db.QueryRow(`
		SELECT id, name, app_id, path_pattern, match_type, methods, status_min, status_max,
		       capture_request, capture_response, max_body_bytes, enabled, created_at, updated_at
		FROM body_audit_rules WHERE id = ?`, id)
	return scanBodyAuditRule(row)
}

func (s *MySQLStore) allowed(userID, appID int64) bool {
	now := time.Now()
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM policies
		WHERE app_id = ? AND effect = 'allow' AND subject = 'user' AND subject_id = ?
		  AND (not_before IS NULL OR not_before <= ?)
		  AND (not_after IS NULL OR not_after >= ?)`,
		appID, userID, now, now,
	).Scan(&count)
	if err == nil && count > 0 {
		return true
	}
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM policies p
		JOIN user_group_members gm ON gm.group_id = p.subject_id
		WHERE p.app_id = ? AND p.effect = 'allow' AND p.subject = 'group' AND gm.user_id = ?
		  AND (p.not_before IS NULL OR p.not_before <= ?)
		  AND (p.not_after IS NULL OR p.not_after >= ?)`,
		appID, userID, now, now,
	).Scan(&count)
	return err == nil && count > 0
}

func (s *MySQLStore) addLoginLog(username, sourceIP, result, reason string) {
	_, _ = s.db.Exec(`INSERT INTO login_logs (username, source_ip, result, failure_reason, created_at) VALUES (?, ?, ?, ?, ?)`, username, sourceIP, result, nullEmptyString(reason), time.Now())
}

func (s *MySQLStore) applyBodyAuditRule(log *model.AccessLog) {
	rule, ok := s.matchBodyAuditRule(*log)
	if !ok {
		log.RequestBody = nil
		log.ResponseBody = nil
		return
	}
	log.BodyRuleID = rule.ID
	if rule.CaptureRequest {
		log.RequestBody = audit.PrepareBodyPayload(log.RequestBody, rule.MaxBodyBytes)
	}
	if rule.CaptureResponse {
		log.ResponseBody = audit.PrepareBodyPayload(log.ResponseBody, rule.MaxBodyBytes)
	}
	if !rule.CaptureRequest {
		log.RequestBody = nil
	}
	if !rule.CaptureResponse {
		log.ResponseBody = nil
	}
	log.HasRequestBody = log.RequestBody != nil
	log.HasResponseBody = log.ResponseBody != nil
}

func (s *MySQLStore) matchBodyAuditRule(log model.AccessLog) (model.BodyAuditRule, bool) {
	for _, rule := range s.ListBodyAuditRules() {
		if bodyAuditRuleMatches(rule, log) {
			return rule, true
		}
	}
	return model.BodyAuditRule{}, false
}

func (s *MySQLStore) addAccessLogBody(accessLogID int64, direction string, body *model.AuditBodyPayload, createdAt time.Time) {
	if body == nil {
		return
	}
	_, _ = s.db.Exec(`
		INSERT INTO access_log_bodies (access_log_id, direction, content_type, body, original_size, stored_size, truncated, sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		accessLogID, direction, body.ContentType, body.Body, body.OriginalSize, body.StoredSize, body.Truncated, body.SHA256, createdAt,
	)
}

func (s *MySQLStore) loadAccessLogBodies(log *model.AccessLog) {
	rows, err := s.db.Query(`
		SELECT direction, content_type, body, original_size, stored_size, truncated, sha256
		FROM access_log_bodies WHERE access_log_id = ?`, log.ID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var direction string
		body := model.AuditBodyPayload{}
		if err := rows.Scan(&direction, &body.ContentType, &body.Body, &body.OriginalSize, &body.StoredSize, &body.Truncated, &body.SHA256); err != nil {
			continue
		}
		switch direction {
		case "request":
			log.RequestBody = &body
			log.HasRequestBody = true
		case "response":
			log.ResponseBody = &body
			log.HasResponseBody = true
		}
	}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner rowScanner) (model.User, error) {
	var user model.User
	var lastLogin sql.NullTime
	if err := scanner.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Status, &user.IsAdmin, &lastLogin, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, ErrNotFound
		}
		return model.User{}, err
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}
	return user, nil
}

func scanApp(scanner rowScanner) (model.App, error) {
	var app model.App
	if err := scanner.Scan(&app.ID, &app.Name, &app.Domain, &app.BackendURL, &app.Enabled, &app.ProxyTimeoutMS, &app.CreatedAt, &app.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.App{}, ErrNotFound
		}
		return model.App{}, err
	}
	return app, nil
}

func scanPolicy(scanner rowScanner) (model.Policy, error) {
	var policy model.Policy
	var notBefore, notAfter sql.NullTime
	if err := scanner.Scan(&policy.ID, &policy.AppID, &policy.Subject, &policy.SubjectID, &policy.Effect, &notBefore, &notAfter, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Policy{}, ErrNotFound
		}
		return model.Policy{}, err
	}
	if notBefore.Valid {
		policy.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		policy.NotAfter = &notAfter.Time
	}
	return policy, nil
}

func scanBodyAuditRule(scanner rowScanner) (model.BodyAuditRule, error) {
	var rule model.BodyAuditRule
	var appID sql.NullInt64
	var methods sql.NullString
	var statusMin, statusMax sql.NullInt64
	if err := scanner.Scan(
		&rule.ID, &rule.Name, &appID, &rule.PathPattern, &rule.MatchType, &methods, &statusMin, &statusMax,
		&rule.CaptureRequest, &rule.CaptureResponse, &rule.MaxBodyBytes, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.BodyAuditRule{}, ErrNotFound
		}
		return model.BodyAuditRule{}, err
	}
	if appID.Valid {
		rule.AppID = appID.Int64
	}
	if methods.Valid && methods.String != "" {
		for _, method := range strings.Split(methods.String, ",") {
			method = strings.TrimSpace(method)
			if method != "" {
				rule.Methods = append(rule.Methods, method)
			}
		}
	}
	if statusMin.Valid {
		rule.StatusMin = int(statusMin.Int64)
	}
	if statusMax.Valid {
		rule.StatusMax = int(statusMax.Int64)
	}
	return rule, nil
}

func scanAccessLog(scanner rowScanner) (model.AccessLog, error) {
	var log model.AccessLog
	var appID, userID, bodyRuleID sql.NullInt64
	var username sql.NullString
	if err := scanner.Scan(
		&log.ID, &appID, &userID, &username, &log.SourceIP, &log.Domain, &log.Path, &log.Method, &log.StatusCode, &log.DurationMS,
		&log.ProxyResult, &log.UserAgent, &log.Browser, &log.OS, &bodyRuleID, &log.HasRequestBody, &log.HasResponseBody, &log.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AccessLog{}, ErrNotFound
		}
		return model.AccessLog{}, err
	}
	if appID.Valid {
		log.AppID = appID.Int64
	}
	if userID.Valid {
		log.UserID = userID.Int64
	}
	if username.Valid {
		log.Username = username.String
	}
	if bodyRuleID.Valid {
		log.BodyRuleID = bodyRuleID.Int64
	}
	return log, nil
}

func scanLoginLog(scanner rowScanner) (model.LoginLog, error) {
	var log model.LoginLog
	var reason sql.NullString
	if err := scanner.Scan(&log.ID, &log.Username, &log.SourceIP, &log.Result, &reason, &log.CreatedAt); err != nil {
		return model.LoginLog{}, err
	}
	if reason.Valid {
		log.FailureReason = reason.String
	}
	return log, nil
}

func scanAdminLog(scanner rowScanner) (model.AdminLog, error) {
	var log model.AdminLog
	var objectID sql.NullInt64
	var before, after sql.NullString
	if err := scanner.Scan(&log.ID, &log.AdminUserID, &log.AdminUsername, &log.ObjectType, &objectID, &log.Action, &before, &after, &log.CreatedAt); err != nil {
		return model.AdminLog{}, err
	}
	if objectID.Valid {
		log.ObjectID = objectID.Int64
	}
	if before.Valid {
		log.BeforeSummary = before.String
	}
	if after.Valid {
		log.AfterSummary = after.String
	}
	return log, nil
}

func replaceGroupMembers(tx *sql.Tx, groupID int64, userIDs []int64, now time.Time) error {
	if _, err := tx.Exec(`DELETE FROM user_group_members WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	for _, userID := range userIDs {
		if _, err := tx.Exec(`INSERT INTO user_group_members (group_id, user_id, created_at) VALUES (?, ?, ?)`, groupID, userID, now); err != nil {
			return err
		}
	}
	return nil
}

func rowsAffected(result sql.Result) int64 {
	count, err := result.RowsAffected()
	if err != nil {
		return 0
	}
	return count
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullEmptyString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
