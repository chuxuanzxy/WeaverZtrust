package audit

import "strings"

func ParseUserAgent(ua string) (browser string, os string) {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/"):
		browser = "Edge"
	case strings.Contains(lower, "chrome/") || strings.Contains(lower, "crios/"):
		browser = "Chrome"
	case strings.Contains(lower, "firefox/"):
		browser = "Firefox"
	case strings.Contains(lower, "safari/"):
		browser = "Safari"
	default:
		browser = "Other"
	}

	switch {
	case strings.Contains(lower, "windows"):
		os = "Windows"
	case strings.Contains(lower, "mac os x"):
		os = "macOS"
	case strings.Contains(lower, "android"):
		os = "Android"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		os = "iOS"
	case strings.Contains(lower, "linux"):
		os = "Linux"
	default:
		os = "Other"
	}
	return browser, os
}
