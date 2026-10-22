package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func testConfig() Config {
	return Config{APIRoot: "/api", APIKey: "test-only", BufferSeconds: 300, ActiveTTL: 300,
		RecentIPTTL: 300, RecentIPHistoryLimit: 10, NFTTable: "inet rathole", Host: "127.0.0.1", Port: 0}
}

func counters(in, out, drop int64) map[string]any {
	list := []any{}
	for _, c := range []struct {
		dir string
		v   int64
	}{{"in", in}, {"out", out}, {"drop", drop}} {
		list = append(list, map[string]any{"counter": map[string]any{"name": "cnt_" + c.dir + "_24000", "bytes": json.Number(fmt.Sprint(c.v))}})
	}
	return map[string]any{"nftables": list}
}

func history(s *Service) []sample { return s.stats[24000].history }

// The tests below port firewall/tests/test_traffic.py.

func TestInitialCumulativeCountersAreABaseline(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(10_000_000, 4_000_000, 0), 1000, 10)
	if len(history(s)) != 0 {
		t.Fatalf("history = %v", history(s))
	}
	s.recordSnapshot(counters(10_000_100, 4_000_200, 20), 1001, 11)
	x := history(s)[len(history(s))-1]
	if x.InBytes != 100 || x.OutBytes != 200 || x.DropBytes != 20 {
		t.Fatalf("sample = %+v", x)
	}
	if len(s.pending) != 1 {
		t.Fatalf("pending = %d", len(s.pending))
	}
}

func TestIdleCleanupKeepsCounterBaselines(t *testing.T) {
	s := newService(testConfig())
	ttl := s.cfg.ActiveTTL
	s.recordSnapshot(counters(1000, 0, 0), 1000, 10)
	s.recordSnapshot(counters(1100, 0, 0), 1001, 11)
	s.cleanupPorts(1002 + ttl)
	if _, ok := s.active[24000]; ok {
		t.Fatal("port still active")
	}
	if s.stats[24000] == nil {
		t.Fatal("baseline dropped")
	}
	s.recordSnapshot(counters(1150, 0, 0), 1003+ttl, float64(13+ttl))
	if got := history(s)[len(history(s))-1].InBytes; got != 50 {
		t.Fatalf("in_bytes = %d", got)
	}
}

func TestCounterResetsDoNotGenerateSpikes(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(1_000_000, 0, 0), 1000, 10)
	s.recordSnapshot(counters(0, 0, 0), 1001, 11)
	if got := history(s)[len(history(s))-1].InBytes; got != 0 {
		t.Fatalf("in_bytes = %d", got)
	}
	s.recordSnapshot(counters(100, 0, 0), 1002, 12)
	if got := history(s)[len(history(s))-1].InBytes; got != 100 {
		t.Fatalf("in_bytes = %d", got)
	}
}

func TestFullWindowAndSnapshotKeepAllDirections(t *testing.T) {
	s := newService(testConfig())
	buf := s.cfg.BufferSeconds
	for sec := int64(0); sec < buf+31; sec++ {
		s.recordSnapshot(counters(sec*100, sec*200, sec*5), 1000+sec, float64(10+sec))
	}
	h := history(s)
	seen := map[int64]bool{}
	for _, x := range h {
		seen[x.Timestamp] = true
	}
	if len(seen) != len(h) {
		t.Fatal("duplicate timestamps")
	}
	if h[len(h)-1].Timestamp-h[0].Timestamp < buf-1 {
		t.Fatalf("window = %d", h[len(h)-1].Timestamp-h[0].Timestamp)
	}
	last := h[len(h)-1]
	if last.InBytes != 100 || last.OutBytes != 200 {
		t.Fatalf("last = %+v", last)
	}
	snap := s.snapshotData([]int64{24000}, 1000+buf+30)
	got := snap.values[24000].([]sample)
	if !reflect.DeepEqual(got[len(got)-1], last) {
		t.Fatalf("snapshot last = %+v, want %+v", got[len(got)-1], last)
	}
}

func TestSlowPollPreservesVolumeAndDuration(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(100, 0, 0), 1000, 10)
	s.recordSnapshot(counters(600, 0, 0), 1002, 12.5)
	x := history(s)[len(history(s))-1]
	if x.InBytes != 500 || x.IntervalSeconds != 2.5 {
		t.Fatalf("sample = %+v", x)
	}
}

func TestRemovedPortsReleaseState(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(100, 0, 0), 1000, 10)
	s.recordSnapshot(map[string]any{"nftables": []any{}}, 1001, 11)
	if s.stats[24000] != nil || len(s.order) != 0 {
		t.Fatal("port state kept")
	}
}

func TestSchedulerJitterInTheSameWallSecondCombinesDuration(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(1000, 0, 0), 1000, 10)
	s.recordSnapshot(counters(1100, 0, 0), 1001, 11)
	s.recordSnapshot(counters(1200, 0, 0), 1001, 12)
	h := history(s)
	if len(h) != 1 || h[0].InBytes != 200 || h[0].IntervalSeconds != 2 {
		t.Fatalf("history = %+v", h)
	}
}

func TestIPsAreReadFromTheMatchingSetInTheSameSnapshot(t *testing.T) {
	s := newService(testConfig())
	s.recordSnapshot(counters(100, 0, 0), 1000, 10)
	payload := counters(200, 100, 0)
	list := payload["nftables"].([]any)
	for _, p := range [][2]string{{"recent_24000", "192.0.2.1"}, {"recent_out_24000", "192.0.2.2"}, {"recent_25000", "192.0.2.3"}} {
		list = append(list, map[string]any{"set": map[string]any{"name": p[0], "elem": []any{p[1]}}})
	}
	payload["nftables"] = list
	s.recordSnapshot(payload, 1001, 11)
	x := history(s)[len(history(s))-1]
	if !reflect.DeepEqual(x.IncomingIPs, []string{"192.0.2.1"}) || !reflect.DeepEqual(x.OutgoingIPs, []string{"192.0.2.2"}) {
		t.Fatalf("sample = %+v", x)
	}
	if s.pending[0].incoming != `["192.0.2.1"]` || s.pending[0].blocked != `[]` {
		t.Fatalf("pending = %+v", s.pending[0])
	}
}

// Extra coverage for the pure functions.

func TestBuildRulesMatchesPython(t *testing.T) {
	state := map[int64]Policy{
		8080:  {IsPublic: true, AllowedIPs: []string{}},
		443:   {AllowedIPs: []string{"1.2.3.4", "5.6.7.8"}},
		24000: {AllowedIPs: []string{}},
	}
	if got := BuildRules(state, "inet rathole", 120); got != goldenRules {
		t.Fatalf("rules differ:\n%s", got)
	}
	if got := BuildRules(map[int64]Policy{}, "inet rathole", 120); got != goldenEmptyRules {
		t.Fatalf("empty rules differ:\n%s", got)
	}
}

func TestParseHits(t *testing.T) {
	raw := `{"nftables":[{"metainfo":{}},{"set":{"name":"recent_80","elem":[
		{"elem":{"val":"10.0.0.2","timeout":300,"expires":290}},
		{"elem":{"val":"10.0.0.1","timeout":300,"expires":290}},
		" 10.0.0.3 ",
		{"elem":{"val":"10.0.0.2","timeout":300,"expires":100}},
		{"elem":{"val":"","timeout":300}},
		{"val":"10.0.0.4","timeout":300.9,"expires":250}]}},
		{"set":{"name":"recent_81","elem":["10.9.9.9"]}}]}`
	data, err := decodeJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := parseHits("recent_80", items(data), 1000)
	want := []ipHit{{"10.0.0.3", 1000}, {"10.0.0.1", 990}, {"10.0.0.2", 990}, {"10.0.0.4", 950}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hits = %v", got)
	}
}

func TestPythonFormatting(t *testing.T) {
	a, b := 0.1, 0.2
	for f, want := range map[float64]string{2.5: "2.5", 1: "1.0", 1e-05: "1e-05", a + b: "0.30000000000000004", 1e16: "1e+16", 123456.789: "123456.789", 0: "0.0"} {
		if got := formatPyFloat(f); got != want {
			t.Errorf("formatPyFloat(%v) = %s, want %s", f, got, want)
		}
	}
	if got := pyDumps([]string{"1.2.3.4", "a\"b\u00e9\U0001F600"}); got != "[\"1.2.3.4\", \"a\\\"b\\u00e9\\ud83d\\ude00\"]" {
		t.Errorf("pyDumps = %s", got)
	}
	if got := pyDumps([]string{}); got != `[]` {
		t.Errorf("pyDumps empty = %s", got)
	}
	for in, want := range map[string]int64{"5": 5, " +7 ": 7, "1_000": 1000, "-3": -3, "007": 7} {
		if n, ok, _ := pyIntString(in); !ok || n != want {
			t.Errorf("pyIntString(%q) = %d %v", in, n, ok)
		}
	}
	for _, in := range []string{"", "a", "1.0", "1__0", "_1", "+-1", "0x10"} {
		if _, ok, _ := pyIntString(in); ok {
			t.Errorf("pyIntString(%q) accepted", in)
		}
	}
	if _, ok, over := pyIntString("99999999999999999999"); !ok || !over {
		t.Error("overflow not reported")
	}
}

// fakeNFT records nft invocations and answers `list set` with a fixed set.
type fakeNFT struct {
	mu    sync.Mutex
	calls []string
	rules string
	sets  map[string]string
}

func (f *fakeNFT) run(stdin []byte, stdout, _ io.Writer, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	if len(args) == 2 && args[0] == "-f" {
		f.rules = string(stdin)
	}
	if len(args) > 3 && args[1] == "list" && args[2] == "set" {
		if body, ok := f.sets[args[len(args)-1]]; ok && stdout != nil {
			_, _ = io.WriteString(stdout, body)
			return nil
		}
		return fmt.Errorf("no such set")
	}
	return nil
}

func newTestServer(t *testing.T, setup func(db *sql.DB)) (*Service, *httptest.Server, *fakeNFT) {
	t.Helper()
	fake := &fakeNFT{sets: map[string]string{}}
	orig := runNFT
	runNFT = fake.run
	t.Cleanup(func() { runNFT = orig })
	s := newService(testConfig())
	var err error
	if s.db, err = openDB(filepath.Join(t.TempDir(), "firewall.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	if setup != nil {
		setup(s.db)
	}
	if err = initDB(context.Background(), s.db); err != nil {
		t.Fatal(err)
	}
	if s.state, err = loadState(context.Background(), s.db); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(s.Handler(ctx))
	t.Cleanup(func() { cancel(); srv.Close() })
	return s, srv, fake
}

func call(t *testing.T, srv *httptest.Server, method, path, body string, key bool) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, srv.URL+path, r)
	if key {
		req.Header.Set("x-api-key", "test-only")
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func TestHTTPContract(t *testing.T) {
	s, srv, fake := newTestServer(t, nil)
	cases := []struct {
		method, path, body string
		key                bool
		status             int
		want               string
	}{
		{"GET", "/api/ping", "", false, 200, `{"msg":"pong","service":"firewall"}`},
		{"GET", "/api/ports/active", "", false, 422, `{"detail":[{"loc":["header","x-api-key"],"msg":"field required","type":"value_error.missing"}]}`},
		{"GET", "/api/ports/policies/list", "", true, 200, `{"msg":"Port policies listed successfully","data":[]}`},
		{"GET", "/api/ports/80/policy", "", true, 200, `{"msg":"Port policy fetched successfully","data":{"port":80,"is_public":true,"allowed_ips":[]}}`},
		{"GET", "/api/ports/0/policy", "", true, 400, `{"detail":"Invalid port"}`},
		{"GET", "/api/ports/abc/policy", "", true, 422, `{"detail":[{"loc":["path","port"],"msg":"value is not a valid integer","type":"type_error.integer"}]}`},
		{"PUT", "/api/ports/443/policy", `{"is_public":false,"allowed_ips":["1.2.3.4","5.6.7.8"]}`, true, 200,
			`{"msg":"Port policy updated successfully","data":{"port":443,"is_public":false,"allowed_ips":["1.2.3.4","5.6.7.8"]}}`},
		{"PUT", "/api/ports/8080/policy", `{}`, true, 200, `{"msg":"Port policy updated successfully","data":{"port":8080,"is_public":true,"allowed_ips":[]}}`},
		{"PUT", "/api/ports/24000/policy", `{"is_public":false,"allowed_ips":[],"extra":1}`, true, 200,
			`{"msg":"Port policy updated successfully","data":{"port":24000,"is_public":false,"allowed_ips":[]}}`},
		{"PUT", "/api/ports/443/policy", `{"is_public":true,"allowed_ips":["1.2.3.4"]}`, true, 422,
			`{"detail":[{"loc":["body","__root__"],"msg":"allowed_ips must be empty when is_public is true","type":"value_error"}]}`},
		{"PUT", "/api/ports/443/policy", `{"is_public":false,"allowed_ips":["1.2.3.4","01.2.3.4","::1"]}`, true, 422,
			`{"detail":[{"loc":["body","allowed_ips",1],"msg":"value is not a valid IPv4 address","type":"value_error.ipv4address"},{"loc":["body","allowed_ips",2],"msg":"value is not a valid IPv4 address","type":"value_error.ipv4address"}]}`},
		{"PUT", "/api/ports/70000/policy", `{"is_public":true}`, true, 400, `{"detail":"Invalid port"}`},
		{"GET", "/api/ports/policies/list", "", true, 200,
			`{"msg":"Port policies listed successfully","data":[{"port":443,"is_public":false,"allowed_ips":["1.2.3.4","5.6.7.8"]},{"port":8080,"is_public":true,"allowed_ips":[]},{"port":24000,"is_public":false,"allowed_ips":[]}]}`},
		{"DELETE", "/api/ports/8080/policy", "", true, 200, `{"msg":"Port policy deleted successfully","data":{"port":8080,"is_public":true,"allowed_ips":[]}}`},
		{"GET", "/api/ports/active", "", true, 200, `{"msg":"Active ports listed successfully","data":[]}`},
		{"GET", "/api/ports/80/recent-ip-hits?limit=0", "", true, 422,
			`{"detail":[{"loc":["query","limit"],"msg":"ensure this value is greater than or equal to 1","type":"value_error.number.not_ge","ctx":{"limit_value":1}}]}`},
		{"GET", "/api/ports/x/recent-ip-hits?limit=51", "", true, 422,
			`{"detail":[{"loc":["path","port"],"msg":"value is not a valid integer","type":"type_error.integer"},{"loc":["query","limit"],"msg":"ensure this value is less than or equal to 50","type":"value_error.number.not_le","ctx":{"limit_value":50}}]}`},
		{"GET", "/api/ports/80/recent-ip-hits", "", true, 200, `{"msg":"Recent IP hits fetched successfully","data":[]}`},
		{"POST", "/api/ports/traffic/snapshot", `{"ports":[25000,24000,25000]}`, true, 200,
			`{"msg":"Traffic snapshot fetched successfully","data":{"25000":[],"24000":[]}}`},
		{"PUT", "/api/ports/1/policy", "", true, 422, `{"detail":[{"loc":["body"],"msg":"field required","type":"value_error.missing"}]}`},
		{"POST", "/api/ports/active", "", true, 405, `{"detail":"Method Not Allowed"}`},
		{"GET", "/api/nope", "", true, 404, `{"detail":"Not Found"}`},
	}
	for _, c := range cases {
		status, body := call(t, srv, c.method, c.path, c.body, c.key)
		if status != c.status || body != c.want {
			t.Errorf("%s %s: %d %s\nwant %d %s", c.method, c.path, status, body, c.status, c.want)
		}
	}

	req, _ := http.NewRequest("GET", srv.URL+"/api/ports/active", nil)
	req.Header.Set("x-api-key", "wrong")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 403 {
		t.Fatalf("wrong key: %v %v", resp, err)
	}

	if !strings.Contains(fake.rules, "set allow_443 {") || strings.Contains(fake.rules, "cnt_in_8080") || !strings.Contains(fake.rules, "cnt_in_24000") {
		t.Fatalf("last rules:\n%s", fake.rules)
	}
	if fake.calls[0] != "delete table inet rathole" || fake.calls[1] != "-f -" {
		t.Fatalf("calls = %v", fake.calls)
	}

	var stored string
	if err := s.db.QueryRow("SELECT allowed_ips FROM port_policies WHERE port = 443").Scan(&stored); err != nil || stored != `["1.2.3.4", "5.6.7.8"]` {
		t.Fatalf("stored = %q %v", stored, err)
	}

	// Recent hits: live set members are stored, trimmed and returned.
	fake.sets["recent_443"] = `{"nftables":[{"set":{"name":"recent_443","elem":["10.0.0.1","10.0.0.2"]}}]}`
	_, body := call(t, srv, "GET", "/api/ports/443/recent-ip-hits?limit=1", "", true)
	var hits struct {
		Data []ipHit `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &hits); err != nil || len(hits.Data) != 1 || hits.Data[0].IP != "10.0.0.1" {
		t.Fatalf("hits = %s", body)
	}

	// Snapshot samples keep Python's key order and float format.
	s.recordSnapshot(counters(100, 0, 0), 1000, 10)
	s.recordSnapshot(counters(150, 0, 0), 1001, 11)
	b, _ := json.Marshal(s.snapshotData([]int64{24000}, 1001))
	if string(b) != `{"24000":[{"timestamp":1001,"interval_seconds":1.0,"in_bytes":50,"out_bytes":0,"drop_bytes":0,"incoming_ips":[],"outgoing_ips":[],"blocked_ips":[]}]}` {
		t.Fatalf("snapshot = %s", b)
	}
}

func TestDBWriterAndMigration(t *testing.T) {
	s, _, _ := newTestServer(t, func(db *sql.DB) {
		for _, q := range []string{
			`CREATE TABLE traffic_buffer (port INTEGER NOT NULL, ts INTEGER NOT NULL, in_bytes INTEGER NOT NULL, out_bytes INTEGER NOT NULL)`,
			`CREATE TABLE allowlists (port INTEGER PRIMARY KEY, ips TEXT)`,
			`INSERT INTO allowlists VALUES (5000, '["9.9.9.9"]')`,
		} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
	})
	if p := s.state[5000]; p.IsPublic || !reflect.DeepEqual(p.AllowedIPs, []string{"9.9.9.9"}) {
		t.Fatalf("migrated state = %+v", s.state)
	}
	now := int64(4_000_000_000)
	err := s.writeBatch(context.Background(), []pendingRow{{port: 24000, ts: now, in: 1, out: 2, drop: 3, blocked: "[]", incoming: `["1.1.1.1"]`, outgoing: "[]"}},
		[]recentRow{{24000, "1.1.1.1", now}}, []int64{24000}, now-300)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var incoming string
	if err := s.db.QueryRow("SELECT drop_bytes, incoming_ips FROM traffic_buffer WHERE port = 24000").Scan(&n, &incoming); err != nil || n != 3 || incoming != `["1.1.1.1"]` {
		t.Fatalf("traffic_buffer = %d %q %v", n, incoming, err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM recent_ip_hits").Scan(&n); err != nil || n != 1 {
		t.Fatalf("recent_ip_hits = %d %v", n, err)
	}
}
