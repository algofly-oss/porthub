package trafficroutes

import (
	"regexp"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/routes/connections"
	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
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
	pymodel.Body     `json:"-"`
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
func normalizedItems(m *pymodel.Model, value any, loc string, lower bool) ([]string, bool) {
	items, typeErr := pymodel.Iterate(value)
	if typeErr != "" {
		m.Add(typeErr, "type_error", nil, loc)
		return nil, false
	}
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		s := ""
		if pymodel.Truthy(item) {
			s = pymodel.PyStr(item)
		}
		s = pymodel.Strip(s)
		if lower {
			s = pymodel.Lower(s)
		}
		if s == "" {
			continue
		}
		if lower && !connections.ValidHostname(s) {
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
func parseRoute(m *pymodel.Model) (routeInput, error) {
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
	if !pymodel.Truthy(hosts) {
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
	if pymodel.Truthy(mode) {
		modeStr = pymodel.PyStr(mode)
	}
	in.TargetMode = pymodel.Lower(pymodel.Strip(modeStr))
	if in.TargetMode != "manual" && in.TargetMode != "connection" {
		m.Add("target_mode must be either manual or connection", "value_error", nil, "targetMode")
	}

	if target, present := m.Value("targetUrl", "target_url"); present && target != nil && target != "" {
		normalized := pymodel.Strip(pymodel.PyStr(target))
		if targetSchemeRE.MatchString(normalized) {
			in.TargetURL = &normalized
		} else {
			m.Add("target_url must include a scheme like http:// or tcp://", "value_error", nil, "targetUrl")
		}
	}

	entries, _ := m.Value("entryPoints", "entry_points")
	if !pymodel.Truthy(entries) {
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

	targetURL := pymodel.Strip(deref(in.TargetURL))
	connectionID := pymodel.Strip(deref(in.ConnectionDataID))
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
		if strings.TrimFunc(h, pymodel.IsSpace) != "" {
			out = append(out, pymodel.Lower(pymodel.Strip(h)))
		}
	}
	return out
}

func (in routeInput) normalizedTargetURL() string { return pymodel.Strip(deref(in.TargetURL)) }

func (in routeInput) normalizedEntryPoints() []string {
	out := []string{}
	for _, e := range in.EntryPoints {
		if s := pymodel.Strip(e); s != "" {
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
	DataID       string `json:"data_id" example:"67f7d26b760bd71f4d3f3c34"`
	pymodel.Body `json:"-"`
}
