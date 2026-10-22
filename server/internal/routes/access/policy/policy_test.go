package policy

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type policyVectors struct {
	Policy struct {
		Machines  []map[string]any          `json:"machines"`
		Groups    map[string]map[string]any `json:"groups"`
		Books     []map[string]any          `json:"books"`
		Grants    []Grant                   `json:"grants"`
		Decisions []struct {
			Source      string   `json:"source"`
			Destination string   `json:"destination"`
			Protocol    string   `json:"protocol"`
			Port        int      `json:"port"`
			Result      Decision `json:"result"`
		} `json:"decisions"`
	} `json:"policy"`
	Names struct {
		Machines  []map[string]any    `json:"machines"`
		Peers     []map[string]any    `json:"peers"`
		Primary   map[string]string   `json:"primary"`
		Aliases   map[string][]string `json:"aliases"`
		Conflicts []struct {
			Label     string `json:"label"`
			MachineID string `json:"machine_id"`
			Clash     any    `json:"clash"`
		} `json:"conflicts"`
	} `json:"names"`
}

func loadPolicyVectors(t *testing.T) policyVectors {
	data, err := os.ReadFile("testdata/pydantic_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v policyVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEvaluateAccessMatchesPython(t *testing.T) {
	v := loadPolicyVectors(t).Policy
	byID := map[string]map[string]any{}
	for _, m := range v.Machines {
		byID[m["_id"].(string)] = m
	}
	if len(v.Decisions) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Decisions {
		got := EvaluateAccess(byID[c.Source], byID[c.Destination], c.Protocol, c.Port, v.Books, v.Groups)
		if !reflect.DeepEqual(got, c.Result) {
			t.Errorf("%s->%s %s/%d: got %+v want %+v", c.Source, c.Destination, c.Protocol, c.Port, got, c.Result)
		}
	}
}

func TestCompileGrantsMatchesPython(t *testing.T) {
	v := loadPolicyVectors(t).Policy
	got := CompileGrants(v.Machines, v.Books, v.Groups)
	if !reflect.DeepEqual(got, v.Grants) {
		t.Errorf("got %+v\nwant %+v", got, v.Grants)
	}
	if len(CompileGrants(v.Machines, nil, v.Groups)) != 0 {
		t.Error("no books must compile to no grants")
	}
}

// The compiler and the evaluator must agree for every pair (test_private_overlay).
func TestCompilerMatchesEvaluator(t *testing.T) {
	v := loadPolicyVectors(t).Policy
	grants := CompileGrants(v.Machines, v.Books, v.Groups)
	for _, s := range v.Machines {
		for _, d := range v.Machines {
			// h has enabled: 0, where Python's evaluator (`is False`) and
			// compiler (truthiness) differ; both ports keep that.
			if s["_id"] == d["_id"] || s["_id"] == "h" || d["_id"] == "h" {
				continue
			}
			for _, proto := range []string{"tcp", "udp", "icmp"} {
				for _, port := range []int{22, 23, 53, 8000, 8002, 8003} {
					want := EvaluateAccess(s, d, proto, port, v.Books, v.Groups).Allowed
					got := false
					for _, g := range grants {
						if g.Source == s["_id"] && g.Destination == d["_id"] && (g.Protocol == proto || g.Protocol == "any") {
							inside := len(g.Ports) == 0
							for _, p := range g.Ports {
								inside = inside || (p.Start <= port && port <= p.End)
							}
							got = got || inside
						}
					}
					if got != want {
						t.Errorf("%v->%v %s/%d: grants %v evaluator %v", s["_id"], d["_id"], proto, port, got, want)
					}
				}
			}
		}
	}
}

func TestHostnamesMatchPython(t *testing.T) {
	v := loadPolicyVectors(t).Names
	primary := AssignHostnames(v.Machines, v.Peers)
	want := map[string]string{}
	for k, label := range v.Primary {
		want[Key(k)] = label
	}
	if !reflect.DeepEqual(primary, want) {
		t.Errorf("primary: got %v want %v", primary, want)
	}
	aliases := AliasHostnames(v.Machines, v.Peers, primary)
	wantAliases := map[string][]string{}
	for k, labels := range v.Aliases {
		wantAliases[Key(k)] = labels
	}
	if !reflect.DeepEqual(aliases, wantAliases) {
		t.Errorf("aliases: got %v want %v", aliases, wantAliases)
	}
	if !reflect.DeepEqual(AliasHostnames(v.Machines, v.Peers, nil), wantAliases) {
		t.Error("aliases without primary differ")
	}
	for _, c := range v.Conflicts {
		got, _ := HostnameConflict(c.Label, c.MachineID, v.Machines, v.Peers)
		if !reflect.DeepEqual(got, c.Clash) {
			t.Errorf("conflict %s for %s: got %v want %v", c.Label, c.MachineID, got, c.Clash)
		}
	}
}

func rule(overrides map[string]any) map[string]any {
	r := map[string]any{"id": "ssh", "name": "Development SSH", "sources": []any{map[string]any{"kind": "group", "id": "dev"}},
		"destinations": []any{map[string]any{"kind": "group", "id": "prod"}}, "protocol": "tcp", "ports": "22", "enabled": true}
	for k, v := range overrides {
		r[k] = v
	}
	return r
}

func TestEvaluateAccessCases(t *testing.T) {
	a := map[string]any{"_id": "a", "user_id": "workspace", "private_owner_id": "alice", "group_ids": []any{"dev"}}
	b := map[string]any{"_id": "b", "user_id": "workspace", "private_owner_id": "bob", "group_ids": []any{"prod"}}
	groups := map[string]map[string]any{"dev": {}, "prod": {}, "people": {"user_ids": []any{"alice"}}}
	book := func(r map[string]any) []map[string]any {
		return []map[string]any{{"_id": "book", "user_id": "workspace", "group_id": "dev", "rules": []any{r}}}
	}
	check := func(src, dst map[string]any, proto string, port int, books []map[string]any) Decision {
		return EvaluateAccess(src, dst, proto, port, books, groups)
	}
	d := check(a, b, "tcp", 22, book(rule(nil)))
	if !d.Allowed || *d.RuleID != "ssh" || *d.BookID != "book" || d.Reason != "Development SSH" {
		t.Errorf("one-way allow: %+v", d)
	}
	if check(b, a, "tcp", 22, book(rule(nil))).Allowed {
		t.Error("reverse initiation must need bidirectional")
	}
	if !check(b, a, "tcp", 22, book(rule(map[string]any{"bidirectional": true}))).Allowed {
		t.Error("bidirectional rule")
	}
	if check(a, b, "tcp", 22, nil).Allowed || check(a, b, "tcp", 22, nil).Reason != "No enabled rule allows this connection" {
		t.Error("default deny")
	}
	for port, want := range map[int]bool{22: true, 8000: true, 8090: true, 23: false, 7999: false, 8091: false} {
		if check(a, b, "tcp", port, book(rule(map[string]any{"ports": "22, 8000-8090"}))).Allowed != want {
			t.Errorf("port %d", port)
		}
	}
	if r := check(a, b, "tcp", 0, book(rule(nil))).Reason; r != "Port is outside the supported range" {
		t.Error(r)
	}
	if r := check(a, b, "sctp", 22, book(rule(nil))).Reason; r != "Unsupported protocol or invalid port" {
		t.Error(r)
	}
	disabled := map[string]any{"_id": "b", "user_id": "workspace", "enabled": false}
	if r := check(a, disabled, "tcp", 22, book(rule(nil))).Reason; r != "Both machines must be enabled" {
		t.Error(r)
	}
	other := map[string]any{"_id": "b", "user_id": "another", "group_ids": []any{"prod"}}
	if r := check(a, other, "tcp", 22, book(rule(map[string]any{"protocol": "any", "ports": ""}))).Reason; r != "Machines belong to different workspaces" {
		t.Error(r)
	}
	if !check(a, b, "tcp", 22, book(rule(map[string]any{"sources": []any{map[string]any{"kind": "group", "id": "people"}}}))).Allowed {
		t.Error("user group expands to the users' devices")
	}
	if check(a, b, "tcp", 22, book(rule(map[string]any{"ports": "bad"}))).Allowed {
		t.Error("malformed stored rule must not grant")
	}
	for _, proto := range []string{"tcp", "udp", "icmp"} {
		if !check(a, b, proto, 3333, book(rule(map[string]any{"protocol": "any", "ports": ""}))).Allowed {
			t.Error("any protocol", proto)
		}
	}
}

func TestSelectorAndFingerprint(t *testing.T) {
	_, err := ParseAccessRule(rule(map[string]any{"destinations": []any{map[string]any{"kind": "all", "id": "something-else"}}}))
	if err == nil || !strings.Contains(err.Error(), `Use id "machines" for all machines`) {
		t.Error(err)
	}
	if !Fingerprint.MatchString(strings.Repeat("AB:", 31) + "AB") {
		t.Error("valid fingerprint")
	}
	if Fingerprint.MatchString(strings.Repeat("AB:", 32)) || Fingerprint.MatchString("sha1:insecure") {
		t.Error("invalid fingerprint accepted")
	}
}

func TestPyFloat(t *testing.T) {
	for f, want := range map[float64]string{1: "1.0", 1000: "1000.0", 1.5e-7: "1.5e-07", 1e22: "1e+22", 123.456: "123.456", 0.0001: "0.0001", 1e16: "1e+16", 1234567890123456: "1234567890123456.0"} {
		if got := PyFloat(f); got != want {
			t.Errorf("%v: got %s want %s", f, got, want)
		}
	}
}
