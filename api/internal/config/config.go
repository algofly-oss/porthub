// Package config reads the server deployment environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen                  string
	MongoURI, MongoDatabase string
	SessionCookie           string
	SignupDisabled          bool

	WebProxyDomainSuffix, ServiceDomain string
	PublicBaseURL                       string
	RatholeServerAddress                string
	RatholePort                         int
	TunnelWebSocket                     bool
	TunnelHTTPBaseURL                   string
	TunnelFallbackBaseURLs              string
	TunnelDirectHTTPSBaseURL            string

	// External port range for connections; zero when unrestricted.
	PortRangeStart, PortRangeEnd int

	MachineOnlineTTL         time.Duration
	MachineOfflineAlertGrace time.Duration
	LongPollTimeout          time.Duration
	LongPollInterval         time.Duration

	RatholeDummyName, RatholeDummyToken, RatholeDummyBind string
	RatholeConfigPath, TraefikConfigPath                  string

	FirewallBaseURL, FirewallAPIKey string
	FirewallTimeout                 time.Duration

	// Directory with porthub-client.sh and install.sh (api/assets/client).
	ClientAssetsDir string
	// Directory with the porthub Go client binaries (porthub-<target>), served
	// to machines in place of the Rathole release download.
	ClientBinaryDir string
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

func number(name string, fallback float64, errs *[]string) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		*errs = append(*errs, name+" must be a number")
		return fallback
	}
	return f
}

func seconds(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

func Load() (Config, error) {
	tunnelWebSocket, err := Bool("PORTHUB_TUNNEL_WEBSOCKET", true)
	if err != nil {
		return Config{}, err
	}
	signup, err := Bool("SIGNUP_DISABLED", false)
	if err != nil {
		return Config{}, err
	}
	var errs []string
	c := Config{
		Listen:                   env("PORTHUB_API_LISTEN", "127.0.0.1:47080"),
		MongoURI:                 os.Getenv("MONGO_DATABASE_URI"),
		MongoDatabase:            os.Getenv("MONGO_DATABASE_NAME"),
		SessionCookie:            env("SESSION_COOKIE_NAME", "porthub_session"),
		SignupDisabled:           signup,
		WebProxyDomainSuffix:     strings.ToLower(strings.TrimSpace(os.Getenv("WEB_PROXY_DOMAIN_SUFFIX"))),
		ServiceDomain:            strings.TrimSpace(os.Getenv("PORT_HUB_SERVICE_DOMAIN")),
		PublicBaseURL:            os.Getenv("PORT_HUB_PUBLIC_BASE_URL"),
		RatholeServerAddress:     os.Getenv("RATHOLE_SERVER_ADDRESS"),
		RatholePort:              int(number("RATHOLE_PORT", 2334, &errs)),
		TunnelWebSocket:          tunnelWebSocket,
		TunnelHTTPBaseURL:        os.Getenv("PORT_HUB_HTTP_BASE_URL"),
		TunnelFallbackBaseURLs:   os.Getenv("PORT_HUB_FALLBACK_BASE_URLS"),
		TunnelDirectHTTPSBaseURL: os.Getenv("PORT_HUB_DIRECT_HTTPS_BASE_URL"),

		MachineOnlineTTL:         seconds(number("MACHINE_ONLINE_TTL_SECONDS", 300, &errs)),
		MachineOfflineAlertGrace: seconds(number("MACHINE_OFFLINE_ALERT_GRACE_SECONDS", 60, &errs)),
		LongPollTimeout:          seconds(number("MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS", 25, &errs)),
		LongPollInterval:         seconds(number("MACHINE_CONFIG_LONG_POLL_INTERVAL_SECONDS", 1, &errs)),

		RatholeDummyName:  env("RATHOLE_DUMMY_SERVICE_NAME", "dummy"),
		RatholeDummyToken: env("RATHOLE_DUMMY_SERVICE_TOKEN", "dummy"),
		RatholeDummyBind:  env("RATHOLE_DUMMY_SERVICE_BIND_ADDR", "127.0.0.1:65535"),
		RatholeConfigPath: env("PORTHUB_GATEWAY_CONFIG_PATH", env("RATHOLE_SERVER_CONFIG_PATH", "/runtime/porthub/gateway.toml")),
		TraefikConfigPath: env("TRAEFIK_DYNAMIC_CONFIG_PATH", "/runtime/traefik/traffic-routes.yml"),

		FirewallBaseURL: strings.TrimRight(os.Getenv("FIREWALL_BASE_URL"), "/"),
		FirewallAPIKey:  os.Getenv("FIREWALL_API_KEY"),
		FirewallTimeout: seconds(number("FIREWALL_REQUEST_TIMEOUT_SECONDS", 5, &errs)),

		ClientAssetsDir: env("PORTHUB_CLIENT_ASSETS_DIR", "/app/client"),
		ClientBinaryDir: env("PORTHUB_CLIENT_BINARY_DIR", "/app/client-bin"),
	}
	start, end := strings.TrimSpace(os.Getenv("EXTERNAL_PORT_RANGE_START")), strings.TrimSpace(os.Getenv("EXTERNAL_PORT_RANGE_END"))
	if start != "" || end != "" {
		if start == "" || end == "" {
			errs = append(errs, "EXTERNAL_PORT_RANGE_START and EXTERNAL_PORT_RANGE_END must both be set")
		} else {
			s, err1 := strconv.Atoi(start)
			e, err2 := strconv.Atoi(end)
			switch {
			case err1 != nil || err2 != nil:
				errs = append(errs, "EXTERNAL_PORT_RANGE_START/END must be integers")
			case s < 1 || s > 65535 || e < 1 || e > 65535:
				errs = append(errs, "EXTERNAL_PORT_RANGE_START/END must be between 1 and 65535")
			case s > e:
				errs = append(errs, "EXTERNAL_PORT_RANGE_START must be less than or equal to EXTERNAL_PORT_RANGE_END")
			default:
				c.PortRangeStart, c.PortRangeEnd = s, e
			}
		}
	}
	if os.Getenv("API_SECRET_KEY") == "" {
		errs = append(errs, "Missing API_SECRET_KEY")
	}
	if c.MongoURI == "" || c.MongoDatabase == "" {
		errs = append(errs, "MONGO_DATABASE_URI and MONGO_DATABASE_NAME are required")
	}
	if len(errs) > 0 {
		return c, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return c, nil
}

// PortRangeError mirrors get_external_port_range_error_message ("" when unrestricted).
func (c Config) PortRangeError() string {
	if c.PortRangeStart == 0 {
		return ""
	}
	return fmt.Sprintf("External port must be between %d and %d", c.PortRangeStart, c.PortRangeEnd)
}

func (c Config) PortAllowed(port int) bool {
	return c.PortRangeStart == 0 || (port >= c.PortRangeStart && port <= c.PortRangeEnd)
}
