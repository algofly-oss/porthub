package trafficroutes

import (
	"regexp"
	"strings"

	"github.com/algofly-oss/porthub/api/internal/validation"
)

var (
	targetSchemeRE     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)
	httpTargetSchemeRE = regexp.MustCompile(`(?i)^https?://`)
)

// routeBody documents the TrafficRoute model (router/traffic_routes/models/traffic_route.py).
type routeBody struct {
	UserID           *string  `json:"user_id,omitempty"`
	DataID           *string  `json:"data_id,omitempty"`
	Name             string   `json:"name" minLength:"1" example:"Primary Docs Route"`
	Group            string   `json:"group,omitempty" maxLength:"80"`
	Description      *string  `json:"description,omitempty" example:"Routes docs.example.com traffic to the internal docs server"`
	Hosts            []string `json:"hosts,omitempty" example:"[\"example.com\",\"docs.example.com\"]"`
	TargetMode       string   `json:"targetMode,omitempty" enum:"manual,connection" doc:"target_mode is also accepted" example:"connection"`
	TargetURL        *string  `json:"targetUrl,omitempty" doc:"target_url is also accepted" example:"http://127.0.0.1:18080"`
	EntryPoints      []string `json:"entryPoints,omitempty" doc:"entry_points is also accepted" example:"[\"web\"]"`
	Enabled          *bool    `json:"enabled,omitempty" example:"true"`
	ConnectionDataID *string  `json:"connectionDataId,omitempty" doc:"connection_data_id is also accepted" example:"67f7d26b760bd71f4d3f3c34"`
	validation.Body  `json:"-"`
}

type routeInput struct {
	DataID           *string
	Name             string
	Group            string
	Description      *string
	Hosts            []string
	TargetMode       string
	TargetURL        *string
	EntryPoints      []string
	Enabled          *bool
	ConnectionDataID *string
}

// normalizedItems runs the shared part of the hosts / entry_points
// pre-validators: iterate, str(item or ""), strip, drop empties, dedupe.
func normalizedItems(m *validation.Model, value any, loc string, lower bool) ([]string, bool) {
	items, typeErr := validation.Iterate(value)
	if typeErr != "" {
		m.Add(typeErr, "type_error", nil, loc)
		return nil, false
	}
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		s := ""
		if validation.Truthy(item) {
			s = validation.PyStr(item)
		}
		s = validation.Strip(s)
		if lower {
			s = validation.Lower(s)
		}
		if s == "" {
			continue
		}
		if lower && !validation.ValidHostname(s) {
			m.Add("Invalid host: "+s, "value_error", nil, loc)
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, true
}

// parseRoute validates like pydantic v1 TrafficRoute. Aliased fields take
// the alias first and the snake_case name second.
func parseRoute(m *validation.Model) (routeInput, error) {
	var in routeInput
	m.OptStr(nil, "user_id")
	in.DataID, _ = m.OptStr(nil, "data_id")
	if name, ok := m.ReqStr("name"); ok && m.MinLen(name, 1, "name") {
		in.Name = name
	}
	if group, ok := m.DefStr("", "group"); ok && m.MaxLen(group, 80, "group") {
		in.Group = group
	}
	empty := ""
	in.Description, _ = m.OptStr(&empty, "description")

	hosts, _ := m.Value("hosts")
	if !validation.Truthy(hosts) {
		hosts = []any{}
	}
	if list, ok := normalizedItems(m, hosts, "hosts", true); ok {
		if len(list) == 0 {
			m.Add("At least one host is required", "value_error", nil, "hosts")
		}
		in.Hosts = list
	}

	mode, _ := m.Value("targetMode", "target_mode")
	modeStr := "manual"
	if validation.Truthy(mode) {
		modeStr = validation.PyStr(mode)
	}
	in.TargetMode = validation.Lower(validation.Strip(modeStr))
	if in.TargetMode != "manual" && in.TargetMode != "connection" {
		m.Add("target_mode must be either manual or connection", "value_error", nil, "targetMode")
	}

	if target, present := m.Value("targetUrl", "target_url"); present && target != nil && target != "" {
		normalized := validation.Strip(validation.PyStr(target))
		if targetSchemeRE.MatchString(normalized) {
			in.TargetURL = &normalized
		} else {
			m.Add("target_url must include a scheme like http:// or tcp://", "value_error", nil, "targetUrl")
		}
	}

	entries, _ := m.Value("entryPoints", "entry_points")
	if !validation.Truthy(entries) {
		entries = []any{"web"}
	}
	if list, ok := normalizedItems(m, entries, "entryPoints", false); ok {
		if len(list) == 0 {
			list = []string{"web"}
		}
		in.EntryPoints = list
	}

	in.Enabled, _ = m.OptBool(true, "enabled")
	in.ConnectionDataID, _ = m.OptStr(nil, "connectionDataId", "connection_data_id")
	if !m.OK() {
		return in, m.Err()
	}

	targetURL := validation.Strip(deref(in.TargetURL))
	connectionID := validation.Strip(deref(in.ConnectionDataID))
	switch {
	case in.TargetMode == "connection" && connectionID == "":
		m.Add("connectionDataId is required when targetMode is connection", "value_error", nil, "__root__")
	case in.TargetMode == "manual" && targetURL == "":
		m.Add("targetUrl is required when targetMode is manual", "value_error", nil, "__root__")
	case in.TargetMode == "manual" && !httpTargetSchemeRE.MatchString(targetURL):
		m.Add("targetUrl must use http:// or https:// when targetMode is manual", "value_error", nil, "__root__")
	case in.TargetMode == "connection" && targetURL == "":
		m.Add("targetUrl is required when targetMode is connection", "value_error", nil, "__root__")
	}
	return in, m.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// normalizedHosts / normalizedTargetURL / normalizedEntryPoints mirror the
// TrafficRoute helper methods.
func (in routeInput) normalizedHosts() []string {
	out := []string{}
	for _, h := range in.Hosts {
		if strings.TrimFunc(h, validation.IsSpace) != "" {
			out = append(out, validation.Lower(validation.Strip(h)))
		}
	}
	return out
}

func (in routeInput) normalizedTargetURL() string { return validation.Strip(deref(in.TargetURL)) }

func (in routeInput) normalizedEntryPoints() []string {
	out := []string{}
	for _, e := range in.EntryPoints {
		if s := validation.Strip(e); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"web"}
	}
	return out
}

// deleteBody documents TrafficRouteDelete.
type deleteBody struct {
	DataID          string `json:"data_id" example:"67f7d26b760bd71f4d3f3c34"`
	validation.Body `json:"-"`
}
