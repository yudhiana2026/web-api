package config

import (
	"os"
	"strconv"
	"time"
)

// Config menyimpan seluruh konfigurasi aplikasi termasuk secret keys dan cookie settings
type Config struct {
	Port               string
	Environment        string // "development" atau "production"
	AccessTokenSecret  string
	RefreshTokenSecret string
	CSRFSecret         string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	CookieSecure       bool
	CookieDomain       string
}

// LoadConfig memuat konfigurasi dari environment variables dengan nilai default
func LoadConfig() *Config {
	env := getEnv("APP_ENV", "development")
	isProd := env == "production"

	accessTTLMinutes := getEnvAsInt("ACCESS_TOKEN_TTL_MINUTES", 15)
	refreshTTLDays := getEnvAsInt("REFRESH_TOKEN_TTL_DAYS", 7)

	return &Config{
		Port:               getEnv("PORT", "8080"),
		Environment:        env,
		AccessTokenSecret:  getEnv("ACCESS_TOKEN_SECRET", "super-secret-access-token-key-change-in-production-min-32-chars!"),
		RefreshTokenSecret: getEnv("REFRESH_TOKEN_SECRET", "super-secret-refresh-token-key-change-in-production-min-32-chars!"),
		CSRFSecret:         getEnv("CSRF_SECRET", "super-secret-csrf-key-change-in-production-min-32-chars!"),
		AccessTokenTTL:     time.Duration(accessTTLMinutes) * time.Minute,
		RefreshTokenTTL:    time.Duration(refreshTTLDays) * 24 * time.Hour,
		CookieSecure:       isProd, // true jika production (hanya lewat HTTPS)
		CookieDomain:       getEnv("COOKIE_DOMAIN", ""),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}
