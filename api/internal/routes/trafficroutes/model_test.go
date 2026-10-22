package trafficroutes

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/algofly-oss/porthub/api/internal/validation"
)

// Golden cases were produced by the Python API's pydantic TrafficRoute model
// (pydantic 1.10, Python 3.10) from the porthub image.
type golden struct {
	Body   string         `json:"body"`
	OK     map[string]any `json:"ok"`
	Errors []any          `json:"errors"`
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func ptr[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestRouteModelMatchesPydantic(t *testing.T) {
	raw, err := os.ReadFile("testdata/tr_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string][]golden
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases["route"] {
		v, err := validation.Decode([]byte(c.Body))
		if err != nil {
			t.Fatal(err)
		}
		m := validation.FromObject(v.(*validation.Object))
		in, _ := parseRoute(m)
		if c.Errors != nil {
			got := []any{}
			for _, item := range m.Errors() {
				item.Loc = item.Loc[1:]
				got = append(got, item)
			}
			if !reflect.DeepEqual(normalize(got), normalize(c.Errors)) {
				t.Errorf("%s:\n got errors %v\nwant errors %v", c.Body, normalize(got), c.Errors)
			}
			continue
		}
		if !m.OK() {
			t.Errorf("%s: unexpected errors %v", c.Body, m.Errors())
			continue
		}
		got := normalize(map[string]any{
			"data_id": ptr(in.DataID), "name": in.Name, "group": in.Group, "description": ptr(in.Description),
			"hosts": in.Hosts, "target_mode": in.TargetMode, "target_url": ptr(in.TargetURL),
			"entry_points": in.EntryPoints, "enabled": ptr(in.Enabled), "connection_data_id": ptr(in.ConnectionDataID),
		})
		if !reflect.DeepEqual(got, normalize(c.OK)) {
			t.Errorf("%s:\n got %v\nwant %v", c.Body, got, c.OK)
		}
	}
}
