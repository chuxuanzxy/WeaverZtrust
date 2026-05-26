package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"ztrust/internal/audit"
	"ztrust/internal/auth"
	"ztrust/internal/model"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
)

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

type AccessLogFilter struct {
	Username   string
	SourceIP   string
	Path       string
	StatusCode int
	From       *time.Time
	To         *time.Time
	Limit      int
}

type MemoryStore struct {
	mu         sync.RWMutex
	nextID     int64
	sessionTTL time.Duration

	users      map[int64]model.User
	userByName map[string]int64
	groups     map[int64]model.Group
	apps       map[int64]model.App
	appByHost  map[string]int64
	policies   map[int64]model.Policy
	bodyRules  map[int64]model.BodyAuditRule
	sessions   map[string]Session

	accessLogs []model.AccessLog
	loginLogs  []model.LoginLog
	adminLogs  []model.AdminLog
}

func NewMemoryStore(sessionTTL time.Duration) *MemoryStore {
	return &MemoryStore{
		nextID:     1,
		sessionTTL: sessionTTL,
		users:      map[int64]model.User{},
		userByName: map[string]int64{},
		groups:     map[int64]model.Group{},
		apps:       map[int64]model.App{},
		appByHost:  map[string]int64{},
		policies:   map[int64]model.Policy{},
		bodyRules:  map[int64]model.BodyAuditRule{},
		sessions:   map[string]Session{},
	}
}

func (s *MemoryStore) BootstrapAdmin(username, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	if _, ok := s.userByName[key]; ok {
		return nil
	}
	id := s.id()
	s.users[id] = model.User{ID: id, Username: username, DisplayName: "System Admin", PasswordHash: hash, Status: "active", IsAdmin: true, CreatedAt: now, UpdatedAt: now}
	s.userByName[key] = id
	return nil
}

func (s *MemoryStore) BootstrapApp(name, domain, backend string) error {
	_, err := s.CreateApp(model.App{Name: name, Domain: domain, BackendURL: backend, Enabled: true, ProxyTimeoutMS: 30000})
	return err
}

func (s *MemoryStore) Authenticate(username, password, sourceIP string) (model.User, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.userLocked(username)
	if !ok || user.Status != "active" || !auth.VerifyPassword(user.PasswordHash, password) {
		s.loginLogs = append(s.loginLogs, model.LoginLog{ID: s.id(), Username: username, SourceIP: sourceIP, Result: "failure", FailureReason: "invalid_credentials", CreatedAt: time.Now()})
		return model.User{}, "", ErrUnauthorized
	}
	now := time.Now()
	user.LastLoginAt = &now
	user.UpdatedAt = now
	s.users[user.ID] = user
	token, err := randomToken()
	if err != nil {
		return model.User{}, "", err
	}
	s.sessions[token] = Session{Token: token, UserID: user.ID, ExpiresAt: now.Add(s.sessionTTL)}
	s.loginLogs = append(s.loginLogs, model.LoginLog{ID: s.id(), Username: username, SourceIP: sourceIP, Result: "success", CreatedAt: now})
	return user, token, nil
}

func (s *MemoryStore) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *MemoryStore) UserBySession(token string) (model.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok || time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return model.User{}, false
	}
	user, ok := s.users[session.UserID]
	return user, ok && user.Status == "active"
}

func (s *MemoryStore) CheckAccess(token, host string) (model.User, model.App, error) {
	user, ok := s.UserBySession(token)
	if !ok {
		return model.User{}, model.App{}, ErrUnauthorized
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	appID, ok := s.appByHost[normalizeHost(host)]
	if !ok {
		return user, model.App{}, ErrNotFound
	}
	app := s.apps[appID]
	if !app.Enabled {
		return user, app, ErrForbidden
	}
	if user.IsAdmin || s.allowedLocked(user.ID, app.ID) {
		return user, app, nil
	}
	return user, app, ErrForbidden
}

func (s *MemoryStore) CreateUser(username, displayName, password string, isAdmin bool) (model.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	if _, ok := s.userByName[key]; ok {
		return model.User{}, ErrAlreadyExists
	}
	id := s.id()
	user := model.User{ID: id, Username: username, DisplayName: displayName, PasswordHash: hash, Status: "active", IsAdmin: isAdmin, CreatedAt: now, UpdatedAt: now}
	s.users[id] = user
	s.userByName[key] = id
	return user, nil
}

func (s *MemoryStore) UpdateUser(id int64, displayName, status string, isAdmin bool, password string) (model.User, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return model.User{}, ErrNotFound
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
	user.UpdatedAt = now
	s.users[id] = user
	return user, nil
}

func (s *MemoryStore) DeleteUser(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.users, id)
	delete(s.userByName, strings.ToLower(user.Username))
	for groupID, group := range s.groups {
		group.UserIDs = removeID(group.UserIDs, id)
		group.UpdatedAt = time.Now()
		s.groups[groupID] = group
	}
	for policyID, policy := range s.policies {
		if policy.Subject == "user" && policy.SubjectID == id {
			delete(s.policies, policyID)
		}
	}
	for token, session := range s.sessions {
		if session.UserID == id {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *MemoryStore) ListUsers() []model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.User, 0, len(s.users))
	for _, user := range s.users {
		out = append(out, user)
	}
	return out
}

func (s *MemoryStore) CreateGroup(group model.Group) (model.Group, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	group.ID = s.id()
	group.CreatedAt = now
	group.UpdatedAt = now
	s.groups[group.ID] = group
	return group, nil
}

func (s *MemoryStore) UpdateGroup(group model.Group) (model.Group, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.groups[group.ID]
	if !ok {
		return model.Group{}, ErrNotFound
	}
	if group.Name != "" {
		current.Name = group.Name
	}
	current.UserIDs = group.UserIDs
	current.UpdatedAt = now
	s.groups[current.ID] = current
	return current, nil
}

func (s *MemoryStore) DeleteGroup(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return ErrNotFound
	}
	delete(s.groups, id)
	for policyID, policy := range s.policies {
		if policy.Subject == "group" && policy.SubjectID == id {
			delete(s.policies, policyID)
		}
	}
	return nil
}

func (s *MemoryStore) ListGroups() []model.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Group, 0, len(s.groups))
	for _, group := range s.groups {
		out = append(out, group)
	}
	return out
}

func (s *MemoryStore) CreateApp(app model.App) (model.App, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	host := normalizeHost(app.Domain)
	if _, ok := s.appByHost[host]; ok {
		return model.App{}, ErrAlreadyExists
	}
	app.ID = s.id()
	app.Domain = host
	app.CreatedAt = now
	app.UpdatedAt = now
	if app.ProxyTimeoutMS == 0 {
		app.ProxyTimeoutMS = 30000
	}
	s.apps[app.ID] = app
	s.appByHost[host] = app.ID
	return app, nil
}

func (s *MemoryStore) UpdateApp(app model.App) (model.App, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.apps[app.ID]
	if !ok {
		return model.App{}, ErrNotFound
	}
	host := normalizeHost(app.Domain)
	if host != "" {
		if existingID, ok := s.appByHost[host]; ok && existingID != app.ID {
			return model.App{}, ErrAlreadyExists
		}
		delete(s.appByHost, current.Domain)
		current.Domain = host
		s.appByHost[host] = app.ID
	}
	if app.Name != "" {
		current.Name = app.Name
	}
	if app.BackendURL != "" {
		current.BackendURL = app.BackendURL
	}
	if app.ProxyTimeoutMS > 0 {
		current.ProxyTimeoutMS = app.ProxyTimeoutMS
	}
	current.Enabled = app.Enabled
	current.UpdatedAt = now
	s.apps[app.ID] = current
	return current, nil
}

func (s *MemoryStore) DeleteApp(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.apps[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.apps, id)
	delete(s.appByHost, app.Domain)
	for policyID, policy := range s.policies {
		if policy.AppID == id {
			delete(s.policies, policyID)
		}
	}
	return nil
}

func (s *MemoryStore) ListApps() []model.App {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.App, 0, len(s.apps))
	for _, app := range s.apps {
		out = append(out, app)
	}
	return out
}

func (s *MemoryStore) CreatePolicy(policy model.Policy) (model.Policy, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	policy.ID = s.id()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	if policy.Effect == "" {
		policy.Effect = "allow"
	}
	s.policies[policy.ID] = policy
	return policy, nil
}

func (s *MemoryStore) DeletePolicy(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return ErrNotFound
	}
	delete(s.policies, id)
	return nil
}

func (s *MemoryStore) ListPolicies() []model.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Policy, 0, len(s.policies))
	for _, policy := range s.policies {
		out = append(out, policy)
	}
	return out
}

func (s *MemoryStore) CreateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error) {
	now := time.Now()
	rule = normalizeBodyAuditRule(rule)
	s.mu.Lock()
	defer s.mu.Unlock()
	rule.ID = s.id()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	s.bodyRules[rule.ID] = rule
	return rule, nil
}

func (s *MemoryStore) UpdateBodyAuditRule(rule model.BodyAuditRule) (model.BodyAuditRule, error) {
	now := time.Now()
	rule = normalizeBodyAuditRule(rule)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.bodyRules[rule.ID]
	if !ok {
		return model.BodyAuditRule{}, ErrNotFound
	}
	rule.CreatedAt = current.CreatedAt
	rule.UpdatedAt = now
	s.bodyRules[rule.ID] = rule
	return rule, nil
}

func (s *MemoryStore) DeleteBodyAuditRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bodyRules[id]; !ok {
		return ErrNotFound
	}
	delete(s.bodyRules, id)
	return nil
}

func (s *MemoryStore) ListBodyAuditRules() []model.BodyAuditRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.BodyAuditRule, 0, len(s.bodyRules))
	for _, rule := range s.bodyRules {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *MemoryStore) AddAccessLog(log model.AccessLog) model.AccessLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.ID = s.id()
	log.CreatedAt = time.Now()
	if log.AppID == 0 {
		log.AppID = s.appIDForDomainLocked(log.Domain)
	}
	s.applyBodyAuditRuleLocked(&log)
	s.accessLogs = append(s.accessLogs, log)
	return log
}

func (s *MemoryStore) AddAdminLog(log model.AdminLog) model.AdminLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.ID = s.id()
	log.CreatedAt = time.Now()
	s.adminLogs = append(s.adminLogs, log)
	return log
}

func (s *MemoryStore) ListAccessLogs(filter AccessLogFilter) []model.AccessLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	matched := make([]model.AccessLog, 0, len(s.accessLogs))
	for _, item := range s.accessLogs {
		if filter.Username != "" && item.Username != filter.Username {
			continue
		}
		if filter.SourceIP != "" && item.SourceIP != filter.SourceIP {
			continue
		}
		if filter.Path != "" && !strings.Contains(item.Path, filter.Path) {
			continue
		}
		if filter.StatusCode != 0 && item.StatusCode != filter.StatusCode {
			continue
		}
		if filter.From != nil && item.CreatedAt.Before(*filter.From) {
			continue
		}
		if filter.To != nil && item.CreatedAt.After(*filter.To) {
			continue
		}
		matched = append(matched, stripAccessLogBodies(item))
	}
	return tail(matched, filter.Limit)
}

func (s *MemoryStore) GetAccessLog(id int64) (model.AccessLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.accessLogs {
		if item.ID == id {
			return item, nil
		}
	}
	return model.AccessLog{}, ErrNotFound
}

func (s *MemoryStore) ListLoginLogs(limit int) []model.LoginLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return tail(s.loginLogs, limit)
}

func (s *MemoryStore) ListAdminLogs(limit int) []model.AdminLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return tail(s.adminLogs, limit)
}

func (s *MemoryStore) userLocked(username string) (model.User, bool) {
	id, ok := s.userByName[strings.ToLower(username)]
	if !ok {
		return model.User{}, false
	}
	user, ok := s.users[id]
	return user, ok
}

func (s *MemoryStore) allowedLocked(userID, appID int64) bool {
	now := time.Now()
	allowed := false
	for _, policy := range s.policies {
		if policy.AppID != appID || policy.Effect != "allow" {
			continue
		}
		if policy.NotBefore != nil && now.Before(*policy.NotBefore) {
			continue
		}
		if policy.NotAfter != nil && now.After(*policy.NotAfter) {
			continue
		}
		switch policy.Subject {
		case "user":
			if policy.SubjectID == userID {
				allowed = true
			}
		case "group":
			group, ok := s.groups[policy.SubjectID]
			if !ok {
				continue
			}
			for _, id := range group.UserIDs {
				if id == userID {
					allowed = true
				}
			}
		}
	}
	return allowed
}

func (s *MemoryStore) appIDForDomainLocked(domain string) int64 {
	if id, ok := s.appByHost[normalizeHost(domain)]; ok {
		return id
	}
	return 0
}

func (s *MemoryStore) applyBodyAuditRuleLocked(log *model.AccessLog) {
	rule, ok := s.matchBodyAuditRuleLocked(*log)
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

func (s *MemoryStore) matchBodyAuditRuleLocked(log model.AccessLog) (model.BodyAuditRule, bool) {
	rules := make([]model.BodyAuditRule, 0, len(s.bodyRules))
	for _, rule := range s.bodyRules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	for _, rule := range rules {
		if bodyAuditRuleMatches(rule, log) {
			return rule, true
		}
	}
	return model.BodyAuditRule{}, false
}

func (s *MemoryStore) id() int64 {
	id := s.nextID
	s.nextID++
	return id
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func normalizeHost(host string) string {
	if strings.Contains(host, "://") {
		host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func tail[T any](items []T, limit int) []T {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	start := len(items) - limit
	if start < 0 {
		start = 0
	}
	out := make([]T, len(items[start:]))
	copy(out, items[start:])
	return out
}

func removeID(items []int64, id int64) []int64 {
	out := items[:0]
	for _, item := range items {
		if item != id {
			out = append(out, item)
		}
	}
	return out
}

func normalizeBodyAuditRule(rule model.BodyAuditRule) model.BodyAuditRule {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.PathPattern = strings.TrimSpace(rule.PathPattern)
	rule.MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
	if rule.MatchType == "" {
		rule.MatchType = "prefix"
	}
	methods := make([]string, 0, len(rule.Methods))
	for _, method := range rule.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			methods = append(methods, method)
		}
	}
	rule.Methods = methods
	if rule.MaxBodyBytes <= 0 {
		rule.MaxBodyBytes = audit.DefaultMaxBodyBytes
	}
	return rule
}

func bodyAuditRuleMatches(rule model.BodyAuditRule, log model.AccessLog) bool {
	if !rule.Enabled {
		return false
	}
	if rule.AppID > 0 && rule.AppID != log.AppID {
		return false
	}
	if len(rule.Methods) > 0 && !containsString(rule.Methods, strings.ToUpper(log.Method)) {
		return false
	}
	if rule.StatusMin > 0 && log.StatusCode < rule.StatusMin {
		return false
	}
	if rule.StatusMax > 0 && log.StatusCode > rule.StatusMax {
		return false
	}
	if rule.PathPattern == "" {
		return true
	}
	switch rule.MatchType {
	case "exact":
		return log.Path == rule.PathPattern
	case "contains":
		return strings.Contains(log.Path, rule.PathPattern)
	default:
		return strings.HasPrefix(log.Path, rule.PathPattern)
	}
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func stripAccessLogBodies(log model.AccessLog) model.AccessLog {
	log.RequestBody = nil
	log.ResponseBody = nil
	return log
}
