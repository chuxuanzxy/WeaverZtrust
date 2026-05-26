package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr     string
	Store          string
	MySQLDSN       string
	CookieName     string
	CookieDomain   string
	SessionTTL     time.Duration
	AdminUser      string
	AdminPassword  string
	SeedAppName    string
	SeedAppDomain  string
	SeedAppBackend string
}

func Load() Config {
	return Config{
		ListenAddr:     env("ZTRUST_LISTEN_ADDR", ":8080"),
		Store:          env("ZTRUST_STORE", "memory"),
		MySQLDSN:       os.Getenv("ZTRUST_MYSQL_DSN"),
		CookieName:     env("ZTRUST_COOKIE_NAME", "ztrust_session"),
		CookieDomain:   os.Getenv("ZTRUST_COOKIE_DOMAIN"),
		SessionTTL:     time.Duration(envInt("ZTRUST_SESSION_TTL_SECONDS", 8*3600)) * time.Second,
		AdminUser:      env("ZTRUST_ADMIN_USER", "admin"),
		AdminPassword:  env("ZTRUST_ADMIN_PASSWORD", "admin123456"),
		SeedAppName:    env("ZTRUST_SEED_APP_NAME", "e-cology OA"),
		SeedAppDomain:  os.Getenv("ZTRUST_SEED_APP_DOMAIN"),
		SeedAppBackend: os.Getenv("ZTRUST_SEED_APP_BACKEND"),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
