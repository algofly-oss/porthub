package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// sample is one per-second traffic entry (key order as in sampler.py).
type sample struct {
	Timestamp       int64    `json:"timestamp"`
	IntervalSeconds pyFloat  `json:"interval_seconds"`
	InBytes         int64    `json:"in_bytes"`
	OutBytes        int64    `json:"out_bytes"`
	DropBytes       int64    `json:"drop_bytes"`
	IncomingIPs     []string `json:"incoming_ips"`
	OutgoingIPs     []string `json:"outgoing_ips"`
	BlockedIPs      []string `json:"blocked_ips"`
}

func (x sample) clone() sample {
	x.IncomingIPs = append([]string{}, x.IncomingIPs...)
	x.OutgoingIPs = append([]string{}, x.OutgoingIPs...)
	x.BlockedIPs = append([]string{}, x.BlockedIPs...)
	return x
}

type ipHit struct {
	IP       string `json:"ip"`
	LastSeen int64  `json:"last_seen"`
}

// portStat is PORT_STATS[port]: counter baselines (nil = None) and history.
type portStat struct {
	last       [3]*int64 // in, out, drop
	sampledAt  *float64
	history    []sample
	recentHits []ipHit
}

// pendingRow is one traffic_buffer row waiting for the db writer.
type pendingRow struct {
	port, ts, in, out, drop     int64
	blocked, incoming, outgoing string
}

var directions = [3]string{"in", "out", "drop"}

// decodeJSON is json.loads with numbers kept exact.
func decodeJSON(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("extra data")
	}
	return data, nil
}

func items(data map[string]any) []any {
	l, _ := data["nftables"].([]any)
	return l
}

// recordSnapshot mirrors record_snapshot: counters become per-interval
// deltas (first sight and counter resets are baselines), IPs come from the
// sets in the same `nft -j list table` output.
func (s *Service) recordSnapshot(data map[string]any, now int64, sampledAt float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	type counterValues = [3]*int64
	counters := map[int64]*counterValues{}
	var counterOrder []int64
	sets := map[string][]any{}
	for _, it := range items(data) {
		obj, _ := it.(map[string]any)
		if set, ok := obj["set"].(map[string]any); ok {
			if name, ok := set["name"].(string); ok {
				sets[name] = []any{obj}
			}
		}
	}
	for _, it := range items(data) {
		obj, _ := it.(map[string]any)
		counter, _ := obj["counter"].(map[string]any)
		name, _ := counter["name"].(string)
		for d, dir := range directions {
			prefix := "cnt_" + dir + "_"
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			port, ok, overflow := pyIntString(name[len(prefix):])
			if !ok || overflow {
				continue
			}
			var raw any = json.Number("0")
			if v, has := counter["bytes"]; has {
				raw = v
			}
			value, ok := pyInt(raw)
			if !ok {
				continue
			}
			value = max(0, value)
			if port >= 1 && port <= 65535 {
				cv := counters[port]
				if cv == nil {
					cv = &counterValues{}
					counters[port] = cv
					counterOrder = append(counterOrder, port)
				}
				cv[d] = &value
			}
		}
	}

	for _, port := range counterOrder {
		values := counters[port]
		st := s.stats[port]
		if st == nil {
			st = &portStat{}
			s.stats[port] = st
			s.order = append(s.order, port)
		}
		prevTime := st.sampledAt
		duration := 0.0
		if prevTime != nil {
			duration = max(0.001, sampledAt-*prevTime)
		}
		var deltas [3]int64
		for d := range directions {
			value := values[d]
			if value == nil {
				value = st.last[d]
			}
			if prev := st.last[d]; prev != nil && value != nil {
				deltas[d] = max(0, *value-*prev)
			}
			st.last[d] = value
		}
		at := sampledAt
		st.sampledAt = &at
		if prevTime == nil {
			continue
		}

		p := fmt.Sprint(port)
		sourceHits := parseHits("recent_"+p, sets["recent_"+p], now)
		st.recentHits = sourceHits
		var ips [3][]string
		window := max(2, duration+1)
		for d, setName := range [3]string{"recent_" + p, "recent_out_" + p, "blocked_" + p} {
			ips[d] = []string{}
			if deltas[d] == 0 {
				continue
			}
			hits := sourceHits
			if d != 0 {
				hits = parseHits(setName, sets[setName], now)
			}
			for _, h := range hits {
				if float64(h.LastSeen) >= float64(now)-window {
					ips[d] = append(ips[d], h.IP)
				}
			}
		}
		smp := sample{Timestamp: now, IntervalSeconds: pyFloat(duration),
			InBytes: deltas[0], OutBytes: deltas[1], DropBytes: deltas[2],
			IncomingIPs: ips[0], OutgoingIPs: ips[1], BlockedIPs: ips[2]}
		if n := len(st.history); n > 0 && st.history[n-1].Timestamp == now {
			prev := &st.history[n-1]
			prev.InBytes += smp.InBytes
			prev.OutBytes += smp.OutBytes
			prev.DropBytes += smp.DropBytes
			prev.IntervalSeconds += smp.IntervalSeconds
			prev.IncomingIPs = sortedUnion(prev.IncomingIPs, smp.IncomingIPs)
			prev.OutgoingIPs = sortedUnion(prev.OutgoingIPs, smp.OutgoingIPs)
			prev.BlockedIPs = sortedUnion(prev.BlockedIPs, smp.BlockedIPs)
		} else {
			st.history = append(st.history, smp)
			if limit := int(s.cfg.BufferSeconds + 2); len(st.history) > limit {
				st.history = append([]sample(nil), st.history[len(st.history)-limit:]...)
			}
		}
		if deltas != [3]int64{} {
			s.active[port] = now
			s.pending = append(s.pending, pendingRow{port: port, ts: now, in: deltas[0], out: deltas[1], drop: deltas[2],
				blocked: pyDumps(ips[2]), incoming: pyDumps(ips[0]), outgoing: pyDumps(ips[1])})
		}
	}

	// Only a successfully observed removal may discard a counter baseline.
	kept := s.order[:0]
	for _, port := range s.order {
		if counters[port] == nil {
			delete(s.stats, port)
			delete(s.active, port)
			continue
		}
		kept = append(kept, port)
	}
	s.order = kept
	s.cleanupPortsLocked(now)
}

func sortedUnion(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range [][]string{a, b} {
		for _, v := range l {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) cleanupPorts(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPortsLocked(now)
}

func (s *Service) cleanupPortsLocked(now int64) {
	for port, last := range s.active {
		if now-last > s.cfg.ActiveTTL {
			delete(s.active, port)
		}
	}
	// Idle ports keep their last counters; dropping them causes historical
	// cumulative bytes to be reported again when traffic resumes.
	for _, st := range s.stats {
		i := 0
		for i < len(st.history) && st.history[i].Timestamp < now-s.cfg.BufferSeconds {
			i++
		}
		if i > 0 {
			st.history = append([]sample(nil), st.history[i:]...)
		}
	}
}

// parseHits mirrors _list_source_ip_hits_for_set on a decoded payload's
// "nftables" list: unique IPs with last_seen from timeout - expires, newest
// first, then by IP.
func parseHits(setName string, list []any, now int64) []ipHit {
	seen := []ipHit{}
	seenIPs := map[string]bool{}
	for _, it := range list {
		obj, _ := it.(map[string]any)
		set, _ := obj["set"].(map[string]any)
		if len(set) == 0 || set["name"] != setName {
			continue
		}
		elems, _ := set["elem"].([]any)
		for _, e := range elems {
			ip, timeout, expires, ok := extractHit(e)
			if !ok {
				continue
			}
			lastSeen := now
			if timeout != nil && expires != nil {
				lastSeen = now - max(0, *timeout-*expires)
			}
			if ip != "" && !seenIPs[ip] {
				seenIPs[ip] = true
				seen = append(seen, ipHit{IP: ip, LastSeen: lastSeen})
			}
		}
	}
	sort.SliceStable(seen, func(i, j int) bool {
		if seen[i].LastSeen != seen[j].LastSeen {
			return seen[i].LastSeen > seen[j].LastSeen
		}
		return seen[i].IP < seen[j].IP
	})
	return seen
}

func extractHit(v any) (ip string, timeout, expires *int64, ok bool) {
	switch x := v.(type) {
	case string:
		ip = strings.TrimSpace(x)
		return ip, nil, nil, ip != ""
	case map[string]any:
		if inner, has := x["elem"]; has {
			return extractHit(inner)
		}
		val, isStr := x["val"].(string)
		if !isStr || strings.TrimSpace(val) == "" {
			return "", nil, nil, false
		}
		if n, ok := pyNumber(x["timeout"]); ok {
			timeout = &n
		}
		if n, ok := pyNumber(x["expires"]); ok {
			expires = &n
		}
		return strings.TrimSpace(val), timeout, expires, true
	}
	return "", nil, nil, false
}

// liveHits lists a set with `nft -j list set` (list_recent_source_ip_hits).
func (s *Service) liveHits(setName string) []ipHit {
	args := append([]string{"-j", "list", "set"}, strings.Fields(s.cfg.NFTTable)...)
	raw, err := nftOutput(nil, append(args, setName)...)
	if err != nil {
		return []ipHit{}
	}
	data, err := decodeJSON(raw)
	if err != nil {
		return []ipHit{}
	}
	return parseHits(setName, items(data), time.Now().Unix())
}

// trafficLoop samples the nft table about once a second (traffic_loop).
func (s *Service) trafficLoop(ctx context.Context) {
	args := append([]string{"-j", "list", "table"}, strings.Fields(s.cfg.NFTTable)...)
	for {
		started := time.Now()
		if raw, err := nftOutput(os.Stderr, args...); err == nil {
			if data, err := decodeJSON(raw); err == nil {
				s.recordSnapshot(data, time.Now().Unix(), s.monotonic())
			}
		}
		wait := max(50*time.Millisecond, time.Second-time.Since(started))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Service) monotonic() float64 { return time.Since(s.epoch).Seconds() }

// snapshotData returns history samples within the buffer for each port, in
// request order (POST /ports/traffic/snapshot).
func (s *Service) snapshotData(ports []int64, now int64) portSamples {
	cutoff := now - s.cfg.BufferSeconds
	s.mu.Lock()
	defer s.mu.Unlock()
	out := portSamples{}
	for _, port := range ports {
		list := []sample{}
		if st := s.stats[port]; st != nil {
			for _, x := range st.history {
				if x.Timestamp >= cutoff {
					list = append(list, x.clone())
				}
			}
		}
		out.set(port, list)
	}
	return out
}

// latestData is the websocket payload: each port's newest sample within the
// buffer, in PORT_STATS order.
func (s *Service) latestData(now int64) portSamples {
	cutoff := now - s.cfg.BufferSeconds
	s.mu.Lock()
	defer s.mu.Unlock()
	out := portSamples{}
	for _, port := range s.order {
		st := s.stats[port]
		if len(st.history) == 0 {
			continue
		}
		last := st.history[len(st.history)-1]
		if last.Timestamp < cutoff {
			continue
		}
		out.set(port, last.clone())
	}
	return out
}

// portSamples is a JSON object keyed by port that keeps insertion order,
// like a Python dict.
type portSamples struct {
	keys   []int64
	values map[int64]any
}

func (p *portSamples) set(port int64, v any) {
	if p.values == nil {
		p.values = map[int64]any{}
	}
	if _, ok := p.values[port]; !ok {
		p.keys = append(p.keys, port)
	}
	p.values[port] = v
}

func (p portSamples) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range p.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%d":`, k)
		v, err := json.Marshal(p.values[k])
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
