package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/algofly-oss/porthub/api/internal/validation"
)

// testdata/pydantic_vectors.json was produced by pydantic 1.10.26 and
// FastAPI 0.79.0 running the original Python models (see gen_vectors.py in
// the port notes): every case must give the same body or 422 detail.

type vectors struct {
	Models []struct {
		Model    string         `json:"model"`
		Body     string         `json:"body"`
		Status   int            `json:"status"`
		Response map[string]any `json:"response"`
	} `json:"models"`
	Ports []struct {
		Value  string  `json:"value"`
		Ranges [][]int `json:"ranges"`
		Error  *string `json:"error"`
	} `json:"ports"`
	Addresses []struct {
		CIDR      string   `json:"cidr"`
		MachineID string   `json:"machine_id"`
		Occupied  []string `json:"occupied"`
		Address   string   `json:"address"`
	} `json:"addresses"`
	Full struct {
		CIDR     string   `json:"cidr"`
		Occupied []string `json:"occupied"`
	} `json:"full"`
	Labels []struct {
		Name  any    `json:"name"`
		Label string `json:"label"`
	} `json:"labels"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/pydantic_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func decode(t *testing.T, body string) any {
	t.Helper()
	v, err := validation.Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func strPtr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func modelDict(name string, raw any) (any, error) {
	switch name {
	case "AccessRule":
		r, err := ParseAccessRule(raw)
		return r.Dict(), err
	case "RuleBook":
		b, err := ParseRuleBook(raw)
		return b.Dict(true), err
	case "NetworkPreferences":
		n, err := ParseNetworkPreferences(raw)
		return n.Dict(), err
	case "DeleteBook":
		d, err := ParseDeleteBook(raw)
		return map[string]any{"revision": d.Revision}, err
	case "GroupMembers":
		g, err := ParseGroupMembers(raw)
		return map[string]any{"machine_ids": g.MachineIDs, "user_ids": g.UserIDs}, err
	case "ConnectionTest":
		c, err := ParseConnectionTest(raw)
		return map[string]any{"source_id": c.SourceID, "destination_id": c.DestinationID, "protocol": c.Protocol, "port": c.Port}, err
	case "Invite":
		i, err := ParseInvite(raw)
		return map[string]any{"email": i.Email, "role": i.Role}, err
	case "InvitationToken":
		s, err := ParseToken(raw, "token")
		return map[string]any{"token": s}, err
	case "Bootstrap":
		s, err := ParseToken(raw, "ticket")
		return map[string]any{"ticket": s}, err
	case "PeerEnrollment":
		p, err := ParsePeerEnrollment(raw)
		return map[string]any{"machine_id": p.MachineID, "hostname": strPtr(p.Hostname), "alias": strPtr(p.Alias)}, err
	case "HostnameChange":
		h, err := ParseHostnameChange(raw)
		return map[string]any{"hostname": strPtr(h)}, err
	case "PeerChange":
		b, err := ParsePeerChange(raw)
		return map[string]any{"enabled": b}, err
	case "ClientSync":
		c, err := ParseClientSync(raw)
		signals := []any{}
		for _, s := range c.Signals {
			signals = append(signals, map[string]any{"to": s.To, "session": s.Session, "description": s.Description.Dict()})
		}
		return map[string]any{"peer_id": c.PeerID, "token": c.Token, "fingerprint": c.Fingerprint, "instance": c.Instance,
			"signals": signals, "acks": c.Acks, "paths": c.Paths}, err
	}
	panic(name)
}

// normal round-trips through JSON so Go and Python values compare equal.
func normal(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestModelsMatchPydantic(t *testing.T) {
	for _, c := range loadVectors(t).Models {
		raw := decode(t, c.Body)
		got, err := modelDict(c.Model, raw)
		var gotResponse any
		status := 200
		if raw == nil {
			status = 422
			gotResponse = map[string]any{"detail": MissingBody()}
		} else if err != nil {
			status = 422
			gotResponse = map[string]any{"detail": Prefix(err, "body")}
		} else {
			gotResponse = got
		}
		want := normal(t, c.Response)
		if status != c.Status || !reflect.DeepEqual(normal(t, gotResponse), want) {
			g, _ := json.Marshal(gotResponse)
			w, _ := json.Marshal(want)
			t.Errorf("%s %s\n got %d %s\nwant %d %s", c.Model, c.Body, status, g, c.Status, w)
		}
	}
}

func TestParsePortsMatchesPython(t *testing.T) {
	for _, c := range loadVectors(t).Ports {
		ranges, err := ParsePorts(c.Value)
		if c.Error != nil {
			if err == nil || err.Error() != *c.Error {
				t.Errorf("%q: got %v %v, want error %q", c.Value, ranges, err, *c.Error)
			}
			continue
		}
		got := [][]int{}
		for _, r := range ranges {
			got = append(got, []int{r[0], r[1]})
		}
		if err != nil || !reflect.DeepEqual(got, c.Ranges) {
			t.Errorf("%q: got %v %v, want %v", c.Value, got, err, c.Ranges)
		}
	}
}

func set(list []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range list {
		out[s] = true
	}
	return out
}

func TestPrivateAddressMatchesPython(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Addresses {
		got, err := PrivateAddress(c.CIDR, c.MachineID, set(c.Occupied))
		if err != nil || got != c.Address {
			t.Errorf("%s %s: got %s %v, want %s", c.CIDR, c.MachineID, got, err, c.Address)
		}
	}
	if _, err := PrivateAddress(v.Full.CIDR, "overflow", set(v.Full.Occupied)); err != ErrRangeFull {
		t.Errorf("full range: %v", err)
	}
}

func TestHostnameLabelMatchesPython(t *testing.T) {
	for _, c := range loadVectors(t).Labels {
		if got := HostnameLabel(c.Name); got != c.Label {
			t.Errorf("%v: got %q want %q", c.Name, got, c.Label)
		}
	}
}
