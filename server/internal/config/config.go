// Package config reads the same environment variables as the Python API.
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Listen, PythonAPI                   string
	MongoURI, MongoDatabase             string
	SessionCookie                       string
	SignupDisabled                      bool
	WebProxyDomainSuffix, ServiceDomain string
}

// Bool mirrors api/shared/env.py _get_bool_env.
func Bool(name string, fallback bool) (bool, error) {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch v {
	case "":
		return fallback, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s must be one of: 1, 0, true, false, yes, no, on, off", name)
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	signup, err := Bool("SIGNUP_DISABLED", false)
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Listen:               env("PORTHUB_API_LISTEN", "127.0.0.1:47080"),
		PythonAPI:            strings.TrimRight(env("PORTHUB_PYTHON_API_URL", "http://127.0.0.1:47081"), "/"),
		MongoURI:             os.Getenv("MONGO_DATABASE_URI"),
		MongoDatabase:        os.Getenv("MONGO_DATABASE_NAME"),
		SessionCookie:        env("SESSION_COOKIE_NAME", "porthub_session"),
		SignupDisabled:       signup,
		WebProxyDomainSuffix: strings.ToLower(strings.TrimSpace(os.Getenv("WEB_PROXY_DOMAIN_SUFFIX"))),
		ServiceDomain:        strings.TrimSpace(os.Getenv("PORT_HUB_SERVICE_DOMAIN")),
	}
	if c.MongoURI == "" || c.MongoDatabase == "" {
		return c, fmt.Errorf("MONGO_DATABASE_URI and MONGO_DATABASE_NAME are required")
	}
	return c, nil
}
