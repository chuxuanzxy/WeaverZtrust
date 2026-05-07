package httpapi

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ztrust/internal/audit"
	"ztrust/internal/config"
	"ztrust/internal/model"
	"ztrust/internal/store"
)

//go:embed web/*
var webAssets embed.FS

type Server struct {
	cfg   config.Config
	store store.Backend
	mux   *http.ServeMux
}

func NewServer(cfg config.Config, st store.Backend) http.Handler {
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux()}
	s.routes()
	return withSecurityHeaders(s.mux)
}

func (s *Server) routes() {
	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(webRoot))
	s.mux.Handle("GET /ui/", http.StripPrefix("/ui/", fileServer))
	s.mux.HandleFunc("GET /", s.index(webRoot))

	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /auth/check", s.check)
	s.mux.HandleFunc("POST /auth/login", s.login)
	s.mux.HandleFunc("POST /auth/logout", s.logout)
	s.mux.HandleFunc("POST /audit/access", s.accessAudit)
	s.mux.HandleFunc("POST /audit/admin", s.adminAudit)

	s.mux.HandleFunc("GET /admin/me", s.requireAdmin(s.me))
	s.mux.HandleFunc("GET /admin/users", s.requireAdmin(s.listUsers))
	s.mux.HandleFunc("POST /admin/users", s.requireAdmin(s.createUser))
	s.mux.HandleFunc("PUT /admin/users/{id}", s.requireAdmin(s.updateUser))
	s.mux.HandleFunc("DELETE /admin/users/{id}", s.requireAdmin(s.deleteUser))
	s.mux.HandleFunc("GET /admin/groups", s.requireAdmin(s.listGroups))
	s.mux.HandleFunc("POST /admin/groups", s.requireAdmin(s.createGroup))
	s.mux.HandleFunc("PUT /admin/groups/{id}", s.requireAdmin(s.updateGroup))
	s.mux.HandleFunc("DELETE /admin/groups/{id}", s.requireAdmin(s.deleteGroup))
	s.mux.HandleFunc("GET /admin/apps", s.requireAdmin(s.listApps))
	s.mux.HandleFunc("POST /admin/apps", s.requireAdmin(s.createApp))
	s.mux.HandleFunc("PUT /admin/apps/{id}", s.requireAdmin(s.updateApp))
	s.mux.HandleFunc("DELETE /admin/apps/{id}", s.requireAdmin(s.deleteApp))
	s.mux.HandleFunc("GET /admin/policies", s.requireAdmin(s.listPolicies))
	s.mux.HandleFunc("POST /admin/policies", s.requireAdmin(s.createPolicy))
	s.mux.HandleFunc("DELETE /admin/policies/{id}", s.requireAdmin(s.deletePolicy))
	s.mux.HandleFunc("GET /admin/audit/access", s.requireAdmin(s.listAccessLogs))
	s.mux.HandleFunc("GET /admin/audit/login", s.requireAdmin(s.listLoginLogs))
	s.mux.HandleFunc("GET /admin/audit/admin", s.requireAdmin(s.listAdminLogs))
}

func (s *Server) index(webRoot fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, webRoot, "index.html")
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	user, token, err := s.store.Authenticate(req.Username, req.Password, clientIP(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	s.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "expires_in": int(s.cfg.SessionTTL.Seconds())})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.cfg.CookieName); err == nil {
		s.store.Logout(cookie.Value)
	}
	s.clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "login_required")
		return
	}
	host := firstNonEmpty(r.Header.Get("X-Original-Host"), r.Header.Get("X-Forwarded-Host"), r.Host)
	user, app, err := s.store.CheckAccess(cookie.Value, host)
	if err != nil {
		status := http.StatusForbidden
		code := "forbidden"
		if errors.Is(err, store.ErrUnauthorized) {
			status = http.StatusUnauthorized
			code = "login_required"
		}
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
			code = "unknown_application"
		}
		writeError(w, status, code)
		return
	}
	w.Header().Set("X-ZTrust-User-ID", strconv.FormatInt(user.ID, 10))
	w.Header().Set("X-ZTrust-Username", user.Username)
	w.Header().Set("X-ZTrust-App-ID", strconv.FormatInt(app.ID, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) accessAudit(w http.ResponseWriter, r *http.Request) {
	var log model.AccessLog
	if err := decodeJSON(r, &log); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if log.SourceIP == "" {
		log.SourceIP = clientIP(r)
	}
	if log.UserAgent != "" && (log.Browser == "" || log.OS == "") {
		log.Browser, log.OS = audit.ParseUserAgent(log.UserAgent)
	}
	created := s.store.AddAccessLog(log)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	var log model.AdminLog
	if err := decodeJSON(r, &log); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	created := s.store.AddAdminLog(log)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, admin model.User) {
	writeJSON(w, http.StatusOK, admin)
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListUsers())
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, admin model.User) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"is_admin"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	user, err := s.store.CreateUser(req.Username, req.DisplayName, req.Password, req.IsAdmin)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.auditAdmin(admin, "user", user.ID, "create", "", fmt.Sprintf("username=%s", user.Username))
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"is_admin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if id == admin.ID && !req.IsAdmin {
		writeError(w, http.StatusBadRequest, "cannot_remove_own_admin_role")
		return
	}
	user, err := s.store.UpdateUser(id, req.DisplayName, req.Status, req.IsAdmin, req.Password)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "user", user.ID, "update", "", fmt.Sprintf("username=%s status=%s", user.Username, user.Status))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if id == admin.ID {
		writeError(w, http.StatusBadRequest, "cannot_delete_self")
		return
	}
	if err := s.store.DeleteUser(id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "user", id, "delete", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGroups(w http.ResponseWriter, _ *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListGroups())
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, admin model.User) {
	var req model.Group
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	group, err := s.store.CreateGroup(req)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.auditAdmin(admin, "group", group.ID, "create", "", fmt.Sprintf("name=%s", group.Name))
	writeJSON(w, http.StatusCreated, group)
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.Group
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.ID = id
	group, err := s.store.UpdateGroup(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "group", group.ID, "update", "", fmt.Sprintf("name=%s members=%d", group.Name, len(group.UserIDs)))
	writeJSON(w, http.StatusOK, group)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteGroup(id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "group", id, "delete", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listApps(w http.ResponseWriter, _ *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListApps())
}

func (s *Server) createApp(w http.ResponseWriter, r *http.Request, admin model.User) {
	var app model.App
	if err := decodeJSON(r, &app); err != nil || app.Name == "" || app.Domain == "" || app.BackendURL == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	created, err := s.store.CreateApp(app)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.auditAdmin(admin, "app", created.ID, "create", "", fmt.Sprintf("domain=%s backend=%s", created.Domain, created.BackendURL))
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateApp(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var app model.App
	if err := decodeJSON(r, &app); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	app.ID = id
	updated, err := s.store.UpdateApp(app)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "app", updated.ID, "update", "", fmt.Sprintf("domain=%s enabled=%t", updated.Domain, updated.Enabled))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteApp(id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "app", id, "delete", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListPolicies())
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request, admin model.User) {
	var policy model.Policy
	if err := decodeJSON(r, &policy); err != nil || policy.AppID == 0 || policy.Subject == "" || policy.SubjectID == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	created, err := s.store.CreatePolicy(policy)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.auditAdmin(admin, "policy", created.ID, "create", "", fmt.Sprintf("app=%d subject=%s:%d effect=%s", created.AppID, created.Subject, created.SubjectID, created.Effect))
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request, admin model.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeletePolicy(id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.auditAdmin(admin, "policy", id, "delete", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAccessLogs(w http.ResponseWriter, r *http.Request, _ model.User) {
	statusCode, _ := strconv.Atoi(r.URL.Query().Get("status_code"))
	filter := store.AccessLogFilter{
		Username:   r.URL.Query().Get("username"),
		SourceIP:   r.URL.Query().Get("ip"),
		Path:       r.URL.Query().Get("path"),
		StatusCode: statusCode,
		From:       queryTime(r, "from"),
		To:         queryTime(r, "to"),
		Limit:      queryLimit(r),
	}
	writeJSON(w, http.StatusOK, s.store.ListAccessLogs(filter))
}

func (s *Server) listLoginLogs(w http.ResponseWriter, r *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListLoginLogs(queryLimit(r)))
}

func (s *Server) listAdminLogs(w http.ResponseWriter, r *http.Request, _ model.User) {
	writeJSON(w, http.StatusOK, s.store.ListAdminLogs(queryLimit(r)))
}

func (s *Server) requireAdmin(next func(http.ResponseWriter, *http.Request, model.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cfg.CookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "login_required")
			return
		}
		user, ok := s.store.UserBySession(cookie.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, "login_required")
			return
		}
		if !user.IsAdmin {
			writeError(w, http.StatusForbidden, "admin_required")
			return
		}
		next(w, r, user)
	}
}

func (s *Server) auditAdmin(admin model.User, objectType string, objectID int64, action, before, after string) {
	s.store.AddAdminLog(model.AdminLog{
		AdminUserID: admin.ID, AdminUsername: admin.Username, ObjectType: objectType,
		ObjectID: objectID, Action: action, BeforeSummary: before, AfterSummary: after,
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomainForRequest(r),
		Expires:  time.Now().Add(s.cfg.SessionTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	base := &http.Cookie{Name: s.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, base)
	if domain := s.cookieDomainForRequest(r); domain != "" {
		domainCookie := *base
		domainCookie.Domain = domain
		http.SetCookie(w, &domainCookie)
	}
}

func (s *Server) cookieDomainForRequest(r *http.Request) string {
	configured := strings.TrimSpace(strings.ToLower(s.cfg.CookieDomain))
	if configured == "" {
		return ""
	}
	cookieDomain := strings.TrimPrefix(configured, ".")
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == cookieDomain || strings.HasSuffix(host, "."+cookieDomain) {
		return s.cfg.CookieDomain
	}
	return ""
}

func decodeJSON(r *http.Request, dest any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dest)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, store.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already_exists")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return 0, false
	}
	return id, true
}

func queryLimit(r *http.Request) int {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return limit
}

func queryTime(r *http.Request, key string) *time.Time {
	value := r.URL.Query().Get(key)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return &parsed
		}
	}
	return nil
}

func clientIP(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		value := r.Header.Get(header)
		if value == "" {
			continue
		}
		return strings.TrimSpace(strings.Split(value, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}
