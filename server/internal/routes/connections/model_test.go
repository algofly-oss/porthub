package connections

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
)

// Golden cases were produced by the Python API's pydantic models (pydantic
// 1.10, Python 3.10) from the porthub image.
type golden struct {
	Body   string         `json:"body"`
	OK     map[string]any `json:"ok"`
	Errors []any          `json:"errors"`
}

func loadGolden(t *testing.T, file string) map[string][]golden {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]golden{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func model(t *testing.T, body string) *pymodel.Model {
	v, err := pymodel.Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return pymodel.FromObject(v.(*pymodel.Object))
}

// normalize round-trips through JSON so Go and Python values compare equal.
func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func errorsWithoutBody(m *pymodel.Model) []any {
	out := []any{}
	for _, item := range m.Errors() {
		item.Loc = item.Loc[1:]
		out = append(out, item)
	}
	return normalize(out).([]any)
}

func check(t *testing.T, c golden, m *pymodel.Model, ok map[string]any) {
	t.Helper()
	if c.Errors != nil {
		if got := errorsWithoutBody(m); !reflect.DeepEqual(got, normalize(c.Errors)) {
			t.Errorf("%s:\n got errors %v\nwant errors %v", c.Body, got, c.Errors)
		}
		return
	}
	if !m.OK() {
		t.Errorf("%s: unexpected errors %v", c.Body, errorsWithoutBody(m))
		return
	}
	if got := normalize(ok); !reflect.DeepEqual(got, normalize(c.OK)) {
		t.Errorf("%s:\n got %v\nwant %v", c.Body, got, c.OK)
	}
}

func ptr[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestConnectionModelMatchesPydantic(t *testing.T) {
	for _, c := range loadGolden(t, "testdata/conn_cases.json")["connection"] {
		m := model(t, c.Body)
		in, _ := parseConnection(m)
		check(t, c, m, map[string]any{
			"data_id": ptr(in.DataID), "machine_id": in.MachineID, "service_name": in.ServiceName,
			"service_description": ptr(in.ServiceDescription), "internal_ip": in.InternalIP,
			"internal_port": in.InternalPort, "external_port": in.ExternalPort, "enabled": ptr(in.Enabled),
			"auto_refresh_enabled": ptr(in.AutoRefreshEnabled), "auto_refresh_interval_minutes": ptr(in.AutoRefreshIntervalMinutes),
		})
	}
}

func TestFirewallModelsMatchPydantic(t *testing.T) {
	cases := loadGolden(t, "testdata/fw_cases.json")
	for _, c := range cases["firewall"] {
		m := model(t, c.Body)
		in, _ := parseFirewallPolicy(m)
		check(t, c, m, map[string]any{"data_id": in.DataID, "is_public": in.IsPublic, "allowed_ips": in.AllowedIPs})
	}
	for _, c := range cases["snapshot"] {
		m := model(t, c.Body)
		ids, _ := parseSnapshot(m)
		check(t, c, m, map[string]any{"data_ids": ids})
	}
}

func TestAliasFallsBackToFieldName(t *testing.T) {
	m := model(t, `{"machine_id":"m","service_name":"s","internal_port":1,"external_port":2,"internal_ip":"Host.LAN","auto_refresh_enabled":true,"autoRefreshIntervalMinutes":5,"auto_refresh_interval_minutes":7}`)
	in, err := parseConnection(m)
	if err != nil || in.InternalIP != "host.lan" || !*in.AutoRefreshEnabled || *in.AutoRefreshIntervalMinutes != 5 {
		t.Fatalf("got %+v %v", in, err)
	}
}
