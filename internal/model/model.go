package model

import "time"

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	PasswordHash string     `json:"-"`
	Status       string     `json:"status"`
	IsAdmin      bool       `json:"is_admin"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type Group struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	UserIDs   []int64   `json:"user_ids"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type App struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Domain         string    `json:"domain"`
	BackendURL     string    `json:"backend_url"`
	Enabled        bool      `json:"enabled"`
	ProxyTimeoutMS int       `json:"proxy_timeout_ms"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Policy struct {
	ID        int64      `json:"id"`
	AppID     int64      `json:"app_id"`
	Subject   string     `json:"subject"`
	SubjectID int64      `json:"subject_id"`
	Effect    string     `json:"effect"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type AccessLog struct {
	ID              int64             `json:"id"`
	AppID           int64             `json:"app_id,omitempty"`
	UserID          int64             `json:"user_id,omitempty"`
	Username        string            `json:"username,omitempty"`
	SourceIP        string            `json:"source_ip"`
	Domain          string            `json:"domain"`
	Path            string            `json:"path"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	DurationMS      int64             `json:"duration_ms"`
	ProxyResult     string            `json:"proxy_result"`
	UserAgent       string            `json:"user_agent"`
	Browser         string            `json:"browser"`
	OS              string            `json:"os"`
	BodyRuleID      int64             `json:"body_rule_id,omitempty"`
	HasRequestBody  bool              `json:"has_request_body"`
	HasResponseBody bool              `json:"has_response_body"`
	RequestBody     *AuditBodyPayload `json:"request_body,omitempty"`
	ResponseBody    *AuditBodyPayload `json:"response_body,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

type AuditBodyPayload struct {
	ContentType  string `json:"content_type"`
	Body         string `json:"body"`
	OriginalSize int    `json:"original_size,omitempty"`
	StoredSize   int    `json:"stored_size,omitempty"`
	Truncated    bool   `json:"truncated"`
	SHA256       string `json:"sha256,omitempty"`
}

type BodyAuditRule struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	AppID           int64     `json:"app_id,omitempty"`
	PathPattern     string    `json:"path_pattern"`
	MatchType       string    `json:"match_type"`
	Methods         []string  `json:"methods"`
	StatusMin       int       `json:"status_min,omitempty"`
	StatusMax       int       `json:"status_max,omitempty"`
	CaptureRequest  bool      `json:"capture_request"`
	CaptureResponse bool      `json:"capture_response"`
	MaxBodyBytes    int       `json:"max_body_bytes"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type LoginLog struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	SourceIP      string    `json:"source_ip"`
	Result        string    `json:"result"`
	FailureReason string    `json:"failure_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AdminLog struct {
	ID            int64     `json:"id"`
	AdminUserID   int64     `json:"admin_user_id"`
	AdminUsername string    `json:"admin_username"`
	ObjectType    string    `json:"object_type"`
	ObjectID      int64     `json:"object_id,omitempty"`
	Action        string    `json:"action"`
	BeforeSummary string    `json:"before_summary,omitempty"`
	AfterSummary  string    `json:"after_summary,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
