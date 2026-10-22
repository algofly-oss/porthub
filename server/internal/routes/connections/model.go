package connections

import (
	"strings"

	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
)

// ValidHostname mirrors HOSTNAME_RE.fullmatch (re.IGNORECASE):
// 1-253 characters of dot-separated labels, 1-63 of [A-Za-z0-9-] each, not
// starting or ending with "-". Python's case-insensitive class also matches
// U+0130, U+0131, U+017F and U+212A.
func ValidHostname(s string) bool {
	n := len([]rune(s))
	if n < 1 || n > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		r := []rune(label)
		if len(r) < 1 || len(r) > 63 || r[0] == '-' || r[len(r)-1] == '-' {
			return false
		}
		for _, c := range r {
			if !hostnameChar(c) {
				return false
			}
		}
	}
	return true
}

func hostnameChar(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		return true
	case c == 0x130, c == 0x131, c == 0x17f, c == 0x212a:
		return true
	}
	return false
}

// NormalizeInternalIP mirrors Connection.validate_internal_ip (pre, always).
func NormalizeInternalIP(value any) (string, bool) {
	normalized := "0.0.0.0"
	if pymodel.Truthy(value) {
		normalized = pymodel.PyStr(value)
	}
	normalized = pymodel.Strip(normalized)
	if pymodel.ParseIPv4(normalized) {
		return normalized, true
	}
	if ValidHostname(normalized) {
		return pymodel.Lower(normalized), true
	}
	return "", false
}

// connectionBody documents the Connection model (router/connections/models/connection.py).
type connectionBody struct {
	UserID                     *string `json:"user_id,omitempty"`
	DataID                     *string `json:"data_id,omitempty" example:"67f7d26b760bd71f4d3f3c34"`
	MachineID                  string  `json:"machine_id" example:"67f7d26b760bd71f4d3f3c34"`
	ServiceName                string  `json:"service_name" minLength:"1" example:"SSH"`
	ServiceDescription         *string `json:"service_description,omitempty" example:"Secure shell access for my homelab node"`
	InternalIP                 string  `json:"internalIp,omitempty" doc:"IPv4 address or hostname (internal_ip is also accepted)" example:"0.0.0.0"`
	InternalPort               int     `json:"internal_port" minimum:"1" maximum:"65535" example:"22"`
	ExternalPort               int     `json:"external_port" minimum:"1" maximum:"65535" example:"54312"`
	Enabled                    *bool   `json:"enabled,omitempty" example:"true"`
	AutoRefreshEnabled         *bool   `json:"autoRefreshEnabled,omitempty" doc:"auto_refresh_enabled is also accepted" example:"false"`
	AutoRefreshIntervalMinutes *int    `json:"autoRefreshIntervalMinutes,omitempty" minimum:"1" maximum:"10080" doc:"auto_refresh_interval_minutes is also accepted" example:"60"`
	pymodel.Body               `json:"-"`
}

type connectionInput struct {
	DataID                     *string
	MachineID                  string
	ServiceName                string
	ServiceDescription         *string
	InternalIP                 string
	InternalPort               int
	ExternalPort               int
	Enabled                    *bool
	AutoRefreshEnabled         *bool
	AutoRefreshIntervalMinutes *int
}

// parseConnection validates like pydantic v1 Connection. Aliased fields take
// the alias first and the snake_case name second.
func parseConnection(m *pymodel.Model) (connectionInput, error) {
	var in connectionInput
	m.OptStr(nil, "user_id")
	in.DataID, _ = m.OptStr(nil, "data_id")
	in.MachineID, _ = m.ReqStr("machine_id")
	if name, ok := m.ReqStr("service_name"); ok && m.MinLen(name, 1, "service_name") {
		in.ServiceName = name
	}
	empty := ""
	in.ServiceDescription, _ = m.OptStr(&empty, "service_description")
	raw, _ := m.Value("internalIp", "internal_ip")
	if ip, ok := NormalizeInternalIP(raw); ok {
		in.InternalIP = ip
	} else {
		m.Add("Use a valid internal IPv4 address or hostname", "value_error", nil, "internalIp")
	}
	in.InternalPort, _ = m.ReqInt(1, 65535, "internal_port")
	in.ExternalPort, _ = m.ReqInt(1, 65535, "external_port")
	in.Enabled, _ = m.OptBool(true, "enabled")
	in.AutoRefreshEnabled, _ = m.OptBool(false, "autoRefreshEnabled", "auto_refresh_enabled")
	in.AutoRefreshIntervalMinutes, _ = m.OptInt(1, 10080, "autoRefreshIntervalMinutes", "auto_refresh_interval_minutes")
	return in, m.Err()
}

// firewallPolicyBody documents ConnectionFirewallPolicy.
type firewallPolicyBody struct {
	DataID       string   `json:"data_id" example:"67f7d26b760bd71f4d3f3c34"`
	IsPublic     *bool    `json:"is_public,omitempty" example:"true"`
	AllowedIPs   []string `json:"allowed_ips,omitempty" example:"[\"203.0.113.10\"]"`
	pymodel.Body `json:"-"`
}

type firewallPolicyInput struct {
	DataID     string
	IsPublic   bool
	AllowedIPs []string
}

func parseFirewallPolicy(m *pymodel.Model) (firewallPolicyInput, error) {
	var in firewallPolicyInput
	in.DataID, _ = m.ReqStr("data_id")
	in.IsPublic, _ = m.DefBool(true, "is_public")
	if list, ok := m.List("allowed_ips"); ok {
		in.AllowedIPs = []string{}
		for i, item := range list {
			if item == nil {
				m.Add("none is not an allowed value", "type_error.none.not_allowed", nil, "allowed_ips", i)
				continue
			}
			ip, ok := pymodel.IPv4(item)
			if !ok {
				m.Add("value is not a valid IPv4 address", "value_error.ipv4address", nil, "allowed_ips", i)
				continue
			}
			in.AllowedIPs = append(in.AllowedIPs, ip)
		}
	}
	if m.OK() && in.IsPublic && len(in.AllowedIPs) > 0 {
		m.Add("allowed_ips must be empty when is_public is true", "value_error", nil, "__root__")
	}
	return in, m.Err()
}

// dataIDBody documents single data_id bodies (delete / refresh).
type dataIDBody struct {
	DataID       string `json:"data_id" example:"67f7d26b760bd71f4d3f3c34"`
	pymodel.Body `json:"-"`
}

func parseDataID(m *pymodel.Model) (string, error) {
	id, _ := m.ReqStr("data_id")
	return id, m.Err()
}

// snapshotBody documents ConnectionTrafficSnapshotRequest.
type snapshotBody struct {
	DataIDs      []string `json:"data_ids,omitempty"`
	pymodel.Body `json:"-"`
}

func parseSnapshot(m *pymodel.Model) ([]string, error) {
	ids, _ := m.StrList("data_ids")
	return ids, m.Err()
}
