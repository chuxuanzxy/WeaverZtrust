package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"ztrust/internal/model"
)

const DefaultMaxBodyBytes = 64 * 1024

var (
	phonePattern  = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	idCardPattern = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
	textSecrets   = regexp.MustCompile(`(?i)((?:password|passwd|pwd|token|authorization|cookie|session|secret|access_token|refresh_token)\s*[:=]\s*)("[^"]*"|'[^']*'|[^,\s&}]+)`)
)

func PrepareBodyPayload(input *model.AuditBodyPayload, maxBytes int) *model.AuditBodyPayload {
	if input == nil || input.Body == "" {
		return nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}

	originalSize := input.OriginalSize
	if originalSize <= 0 {
		originalSize = len(input.Body)
	}

	body := RedactSensitiveBody(input.Body, input.ContentType)
	body, truncated := truncateUTF8(body, maxBytes)
	sum := sha256.Sum256([]byte(body))

	return &model.AuditBodyPayload{
		ContentType:  strings.TrimSpace(input.ContentType),
		Body:         body,
		OriginalSize: originalSize,
		StoredSize:   len(body),
		Truncated:    truncated || input.Truncated,
		SHA256:       hex.EncodeToString(sum[:]),
	}
}

func RedactSensitiveBody(body, contentType string) string {
	if looksLikeJSON(body, contentType) {
		var value any
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err == nil {
			value = redactJSONValue(value)
			if raw, err := json.Marshal(value); err == nil {
				body = string(raw)
			}
		}
	}

	body = textSecrets.ReplaceAllString(body, `${1}"[REDACTED]"`)
	body = phonePattern.ReplaceAllStringFunc(body, func(value string) string {
		return value[:3] + "****" + value[7:]
	})
	body = idCardPattern.ReplaceAllStringFunc(body, func(value string) string {
		return value[:6] + "********" + value[len(value)-4:]
	})
	return body
}

func looksLikeJSON(body, contentType string) bool {
	contentType = strings.ToLower(contentType)
	trimmed := strings.TrimSpace(body)
	return strings.Contains(contentType, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if isSensitiveKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			typed[key] = redactJSONValue(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = redactJSONValue(item)
		}
		return typed
	default:
		return typed
	}
}

func isSensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, token := range []string{
		"password", "passwd", "pwd", "token", "authorization", "cookie",
		"session", "secret", "access_token", "refresh_token",
	} {
		if strings.Contains(key, token) {
			return true
		}
	}
	return false
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	for maxBytes > 0 && !utf8.ValidString(value[:maxBytes]) {
		maxBytes--
	}
	return value[:maxBytes], true
}
