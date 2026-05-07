package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ztrust/internal/config"
	"ztrust/internal/model"
	"ztrust/internal/store"
)

func TestAuthPolicyAndAuditFlow(t *testing.T) {
	cfg := config.Config{
		CookieName:    "ztrust_session",
		SessionTTL:    time.Hour,
		AdminUser:     "admin",
		AdminPassword: "secret",
	}
	st := store.NewMemoryStore(cfg.SessionTTL)
	if err := st.BootstrapAdmin(cfg.AdminUser, cfg.AdminPassword); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	handler := NewServer(cfg, st)

	adminCookie := login(t, handler, "admin", "secret")

	user := doJSON[model.User](t, handler, http.MethodPost, "/admin/users", adminCookie, map[string]any{
		"username":     "zhangsan",
		"display_name": "Zhang San",
		"password":     "passw0rd",
	})
	app := doJSON[model.App](t, handler, http.MethodPost, "/admin/apps", adminCookie, map[string]any{
		"name":        "e-cology OA",
		"domain":      "www.e-cology.com.cn",
		"backend_url": "http://10.0.0.10",
		"enabled":     true,
	})
	_ = doJSON[model.Policy](t, handler, http.MethodPost, "/admin/policies", adminCookie, map[string]any{
		"app_id":     app.ID,
		"subject":    "user",
		"subject_id": user.ID,
		"effect":     "allow",
	})

	userCookie := login(t, handler, "zhangsan", "passw0rd")
	req := httptest.NewRequest(http.MethodGet, "/auth/check", nil)
	req.AddCookie(userCookie)
	req.Header.Set("X-Original-Host", "www.e-cology.com.cn")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("check status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-ZTrust-Username") != "zhangsan" {
		t.Fatalf("missing username auth header")
	}

	_ = doJSON[model.AccessLog](t, handler, http.MethodPost, "/audit/access", nil, map[string]any{
		"username":     "zhangsan",
		"source_ip":    "192.0.2.10",
		"domain":       "www.e-cology.com.cn",
		"path":         "/workflow/request",
		"method":       "GET",
		"status_code":  200,
		"duration_ms":  18,
		"proxy_result": "200",
		"user_agent":   "Mozilla/5.0 Chrome/120.0 Windows NT 10.0",
	})
	logs := doJSON[[]model.AccessLog](t, handler, http.MethodGet, "/admin/audit/access?username=zhangsan&ip=192.0.2.10&path=workflow&status_code=200", adminCookie, nil)
	if len(logs) != 1 {
		t.Fatalf("filtered access logs length = %d", len(logs))
	}
	if logs[0].Browser != "Chrome" || logs[0].OS != "Windows" {
		t.Fatalf("unexpected UA parse: browser=%s os=%s", logs[0].Browser, logs[0].OS)
	}
}

func TestServesAdminUI(t *testing.T) {
	cfg := config.Config{
		CookieName:    "ztrust_session",
		SessionTTL:    time.Hour,
		AdminUser:     "admin",
		AdminPassword: "secret",
	}
	st := store.NewMemoryStore(cfg.SessionTTL)
	if err := st.BootstrapAdmin(cfg.AdminUser, cfg.AdminPassword); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	handler := NewServer(cfg, st)

	for _, path := range []string{"/", "/ui/app.css", "/ui/app.js"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, rr.Code)
		}
	}
}

func TestLoginCookieDomainMatchesRequestHost(t *testing.T) {
	cfg := config.Config{
		CookieName:    "ztrust_session",
		CookieDomain:  ".e-cology.com.cn",
		SessionTTL:    time.Hour,
		AdminUser:     "admin",
		AdminPassword: "secret",
	}
	st := store.NewMemoryStore(cfg.SessionTTL)
	if err := st.BootstrapAdmin(cfg.AdminUser, cfg.AdminPassword); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	handler := NewServer(cfg, st)

	localCookie := loginHeader(t, handler, "127.0.0.1:8080")
	if strings.Contains(strings.ToLower(localCookie), "domain=") {
		t.Fatalf("local login should use a host-only cookie, got %q", localCookie)
	}

	productionCookie := loginHeader(t, handler, "www.e-cology.com.cn")
	if !strings.Contains(strings.ToLower(productionCookie), "domain=e-cology.com.cn") {
		t.Fatalf("production login should keep configured cookie domain, got %q", productionCookie)
	}
}

func TestAdminCRUDLifecycle(t *testing.T) {
	cfg := config.Config{
		CookieName:    "ztrust_session",
		SessionTTL:    time.Hour,
		AdminUser:     "admin",
		AdminPassword: "secret",
	}
	st := store.NewMemoryStore(cfg.SessionTTL)
	if err := st.BootstrapAdmin(cfg.AdminUser, cfg.AdminPassword); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	handler := NewServer(cfg, st)
	adminCookie := login(t, handler, "admin", "secret")

	me := doJSON[model.User](t, handler, http.MethodGet, "/admin/me", adminCookie, nil)
	if me.Username != "admin" || !me.IsAdmin {
		t.Fatalf("unexpected admin user: %#v", me)
	}

	app := doJSON[model.App](t, handler, http.MethodPost, "/admin/apps", adminCookie, map[string]any{
		"name":        "OA",
		"domain":      "oa.example.test",
		"backend_url": "http://10.0.0.10",
		"enabled":     true,
	})
	app = doJSON[model.App](t, handler, http.MethodPut, "/admin/apps/"+itoa(app.ID), adminCookie, map[string]any{
		"name":        "OA Test",
		"domain":      "oa-test.example.test",
		"backend_url": "http://10.0.0.11",
		"enabled":     false,
	})
	if app.Name != "OA Test" || app.Enabled {
		t.Fatalf("app was not updated: %#v", app)
	}

	user := doJSON[model.User](t, handler, http.MethodPost, "/admin/users", adminCookie, map[string]any{
		"username": "lisi",
		"password": "passw0rd",
	})
	user = doJSON[model.User](t, handler, http.MethodPut, "/admin/users/"+itoa(user.ID), adminCookie, map[string]any{
		"display_name": "Li Si",
		"status":       "disabled",
		"is_admin":     false,
	})
	if user.DisplayName != "Li Si" || user.Status != "disabled" {
		t.Fatalf("user was not updated: %#v", user)
	}

	group := doJSON[model.Group](t, handler, http.MethodPost, "/admin/groups", adminCookie, map[string]any{
		"name":     "灰度用户",
		"user_ids": []int64{user.ID},
	})
	group = doJSON[model.Group](t, handler, http.MethodPut, "/admin/groups/"+itoa(group.ID), adminCookie, map[string]any{
		"name":     "生产灰度用户",
		"user_ids": []int64{},
	})
	if group.Name != "生产灰度用户" || len(group.UserIDs) != 0 {
		t.Fatalf("group was not updated: %#v", group)
	}

	policy := doJSON[model.Policy](t, handler, http.MethodPost, "/admin/policies", adminCookie, map[string]any{
		"app_id":     app.ID,
		"subject":    "group",
		"subject_id": group.ID,
	})
	doNoContent(t, handler, http.MethodDelete, "/admin/policies/"+itoa(policy.ID), adminCookie)
	doNoContent(t, handler, http.MethodDelete, "/admin/groups/"+itoa(group.ID), adminCookie)
	doNoContent(t, handler, http.MethodDelete, "/admin/users/"+itoa(user.ID), adminCookie)
	doNoContent(t, handler, http.MethodDelete, "/admin/apps/"+itoa(app.ID), adminCookie)
}

func loginHeader(t *testing.T, handler http.Handler, host string) string {
	t.Helper()
	req := requestWithJSON(t, http.MethodPost, "/auth/login", map[string]any{"username": "admin", "password": "secret"})
	req.Host = host
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatalf("login did not return Set-Cookie")
	}
	return cookies[0]
}

func login(t *testing.T, handler http.Handler, username, password string) *http.Cookie {
	t.Helper()
	req := requestWithJSON(t, http.MethodPost, "/auth/login", map[string]any{"username": username, "password": password})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rr.Code, rr.Body.String())
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "ztrust_session" {
			return cookie
		}
	}
	t.Fatalf("login did not set session cookie")
	return nil
}

func doNoContent(t *testing.T, handler http.Handler, method, path string, cookie *http.Cookie) {
	t.Helper()
	req := requestWithJSON(t, method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("%s %s status = %d, body = %s", method, path, rr.Code, rr.Body.String())
	}
}

func doJSON[T any](t *testing.T, handler http.Handler, method, path string, cookie *http.Cookie, payload any) T {
	t.Helper()
	req := requestWithJSON(t, method, path, payload)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("%s %s status = %d, body = %s", method, path, rr.Code, rr.Body.String())
	}
	var out T
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func requestWithJSON(t *testing.T, method, path string, payload any) *http.Request {
	t.Helper()
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &body)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}
