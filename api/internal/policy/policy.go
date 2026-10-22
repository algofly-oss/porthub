package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Private-network policy model. No policies means no access. Groups are
// labels, not implicit grants; selectors are explicit. Users represent their
// enrolled devices. Public forwarding is outside this policy engine.

// Selector: kind "all" (id "machines") means every machine in the workspace.
type Selector struct {
	Kind string
	ID   string
}

func (s Selector) Dict() map[string]any { return map[string]any{"kind": s.Kind, "id": s.ID} }

type AccessRule struct {
	ID            string
	Name          string
	Sources       []Selector
	Destinations  []Selector
	Protocol      string
	Ports         string
	Bidirectional bool
	Enabled       bool
}

func (r AccessRule) Dict() map[string]any {
	sel := func(list []Selector) []any {
		out := make([]any, len(list))
		for i, s := range list {
			out[i] = s.Dict()
		}
		return out
	}
	return map[string]any{
		"id": r.ID, "name": r.Name, "sources": sel(r.Sources), "destinations": sel(r.Destinations),
		"protocol": r.Protocol, "ports": r.Ports, "bidirectional": r.Bidirectional, "enabled": r.Enabled,
	}
}

type RuleBook struct {
	Name     string
	GroupID  string
	Enabled  bool
	Rules    []AccessRule
	Revision int64
}

// Dict mirrors RuleBook.dict(); revision is left out when exclude is set.
func (b RuleBook) Dict(withRevision bool) map[string]any {
	rules := make([]any, len(b.Rules))
	for i, r := range b.Rules {
		rules[i] = r.Dict()
	}
	out := map[string]any{"name": b.Name, "group_id": b.GroupID, "enabled": b.Enabled, "rules": rules}
	if withRevision {
		out["revision"] = b.Revision
	}
	return out
}

type NetworkPreferences struct {
	CIDR      string
	DNSSuffix string
}

func (n NetworkPreferences) Dict() map[string]any {
	return map[string]any{"cidr": n.CIDR, "dns_suffix": n.DNSSuffix}
}

func selectorModel(e *errs, loc []any, v any) (Selector, bool) {
	d, ok := dictField(e, loc, v)
	if !ok {
		return Selector{}, false
	}
	n := len(e.items)
	var s Selector
	kindOK := false
	if raw, has := d["kind"]; !has {
		missing(e, at(loc, "kind"))
	} else {
		s.Kind, kindOK = literalField(e, at(loc, "kind"), raw, "machine", "user", "group", "all")
	}
	if raw, has := d["id"]; !has {
		missing(e, at(loc, "id"))
	} else if id, ok := strField(e, at(loc, "id"), raw, 1, 64); ok {
		if kindOK && s.Kind == "all" && id != "machines" {
			e.valueError(at(loc, "id"), `Use id "machines" for all machines`)
		}
		s.ID = id
	}
	return s, len(e.items) == n
}

func selectorList(e *errs, loc []any, v any) []Selector {
	list, ok := listField(e, loc, v, 1, 32)
	if !ok {
		return nil
	}
	out := []Selector{}
	for i, item := range list {
		if s, ok := selectorModel(e, at(loc, i), item); ok {
			out = append(out, s)
		}
	}
	return out
}

func accessRuleModel(e *errs, loc []any, v any) (AccessRule, bool) {
	d, ok := dictField(e, loc, v)
	if !ok {
		return AccessRule{}, false
	}
	n := len(e.items)
	r := AccessRule{Protocol: "tcp", Enabled: true}
	if raw, has := d["id"]; !has {
		missing(e, at(loc, "id"))
	} else {
		r.ID, _ = strField(e, at(loc, "id"), raw, 1, 64)
	}
	if raw, has := d["name"]; !has {
		missing(e, at(loc, "name"))
	} else if name, ok := strField(e, at(loc, "name"), raw, 1, 80); ok {
		if PyStrip(name) == "" {
			e.valueError(at(loc, "name"), "A rule name is required")
		}
		r.Name = PyStrip(name)
	}
	for _, f := range []struct {
		key string
		dst *[]Selector
	}{{"sources", &r.Sources}, {"destinations", &r.Destinations}} {
		if raw, has := d[f.key]; !has {
			missing(e, at(loc, f.key))
		} else {
			*f.dst = selectorList(e, at(loc, f.key), raw)
		}
	}
	protocolOK := true
	if raw, has := d["protocol"]; has {
		r.Protocol, protocolOK = literalField(e, at(loc, "protocol"), raw, "any", "tcp", "udp", "icmp")
	}
	ports := ""
	if raw, has := d["ports"]; has {
		ports, _ = strField(e, at(loc, "ports"), raw, 0, 512)
	}
	if raw, has := d["bidirectional"]; has {
		r.Bidirectional, _ = boolField(e, at(loc, "bidirectional"), raw)
	}
	if raw, has := d["enabled"]; has {
		r.Enabled, _ = boolField(e, at(loc, "enabled"), raw)
	}
	// root_validator: runs even when fields failed, on the valid ones.
	ranges, err := ParsePorts(ports)
	if err != nil {
		e.valueError(at(loc, "__root__"), err.Error())
	} else if len(ranges) > 0 && (!protocolOK || (r.Protocol != "tcp" && r.Protocol != "udp")) {
		e.valueError(at(loc, "__root__"), "Port restrictions require TCP or UDP")
	} else {
		r.Ports = FormatPorts(ranges)
	}
	return r, len(e.items) == n
}

// ParseAccessRule mirrors AccessRule(**raw).dict().
func ParseAccessRule(raw any) (AccessRule, error) {
	e := &errs{}
	r, _ := accessRuleModel(e, nil, raw)
	return r, e.err()
}

// ParseRuleBook mirrors RuleBook(**body).
func ParseRuleBook(raw any) (RuleBook, error) {
	e := &errs{}
	b := RuleBook{Enabled: true, Rules: []AccessRule{}}
	d, ok := dictField(e, nil, raw)
	if !ok {
		return b, e.err()
	}
	if v, has := d["name"]; !has {
		missing(e, []any{"name"})
	} else if name, ok := strField(e, []any{"name"}, v, 1, 80); ok {
		if PyStrip(name) == "" {
			e.valueError([]any{"name"}, "A rule-book name is required")
		}
		b.Name = PyStrip(name)
	}
	if v, has := d["group_id"]; !has {
		missing(e, []any{"group_id"})
	} else {
		b.GroupID, _ = strField(e, []any{"group_id"}, v, 1, 64)
	}
	if v, has := d["enabled"]; has {
		b.Enabled, _ = boolField(e, []any{"enabled"}, v)
	}
	if v, has := d["rules"]; has {
		if list, ok := listField(e, []any{"rules"}, v, 0, 100); ok {
			n := len(e.items)
			for i, item := range list {
				if r, ok := accessRuleModel(e, []any{"rules", i}, item); ok {
					b.Rules = append(b.Rules, r)
				}
			}
			if len(e.items) == n {
				seen := map[string]bool{}
				for _, r := range b.Rules {
					if seen[r.ID] {
						e.valueError([]any{"rules"}, "Rule identifiers must be unique inside a rule book")
						break
					}
					seen[r.ID] = true
				}
			}
		}
	}
	if v, has := d["revision"]; has {
		b.Revision, _ = intField(e, []any{"revision"}, v, i64(0), nil)
	}
	return b, e.err()
}

// ParseNetworkPreferences mirrors NetworkPreferences(**doc) (extra keys ignored).
func ParseNetworkPreferences(raw any) (NetworkPreferences, error) {
	e := &errs{}
	n := NetworkPreferences{CIDR: "10.203.0.0/24", DNSSuffix: "phub"}
	d, ok := dictField(e, nil, raw)
	if !ok {
		return n, e.err()
	}
	if v, has := d["cidr"]; has {
		if s, ok := strField(e, []any{"cidr"}, v, 0, 0); ok {
			if cidr, err := privateIPv4(s); err != nil {
				e.valueError([]any{"cidr"}, err.Error())
			} else {
				n.CIDR = cidr
			}
		}
	}
	if v, has := d["dns_suffix"]; has {
		if s, ok := strField(e, []any{"dns_suffix"}, v, 3, 120); ok {
			if suffix, err := validSuffix(s); err != nil {
				e.valueError([]any{"dns_suffix"}, err.Error())
			} else {
				n.DNSSuffix = suffix
			}
		}
	}
	return n, e.err()
}

// ParsePorts mirrors parse_ports: sorted unique (start, end) ranges.
func ParsePorts(value string) ([][2]int, error) {
	value = PyStrip(value)
	if l := PyLower(value); value == "" || l == "any" || l == "all" || l == "*" {
		return [][2]int{}, nil
	}
	ranges := [][2]int{}
	for _, item := range strings.Split(value, ",") {
		start, end, ok := portItem(item)
		if !ok {
			return nil, errors.New("Use ports such as 22, 443, 8000-8090")
		}
		if !(1 <= start && start <= end && end <= 65535) {
			return nil, errors.New("Ports must be between 1 and 65535, with ranges in ascending order")
		}
		ranges = append(ranges, [2]int{start, end})
	}
	if len(ranges) > 64 {
		return nil, errors.New("Use no more than 64 port entries")
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i][0] != ranges[j][0] {
			return ranges[i][0] < ranges[j][0]
		}
		return ranges[i][1] < ranges[j][1]
	})
	out := [][2]int{}
	for i, r := range ranges {
		if i == 0 || r != ranges[i-1] {
			out = append(out, r)
		}
	}
	return out, nil
}

// portItem matches \s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s* (Unicode \s and \d).
func portItem(item string) (int, int, bool) {
	rs := []rune(item)
	i := 0
	skip := func() {
		for i < len(rs) && IsPySpace(rs[i]) {
			i++
		}
	}
	number := func() (int, bool) {
		n, count := 0, 0
		for i < len(rs) && count < 5 {
			d, ok := digitValue(rs[i])
			if !ok {
				break
			}
			n = n*10 + d
			i++
			count++
		}
		return n, count > 0
	}
	skip()
	start, ok := number()
	if !ok {
		return 0, 0, false
	}
	end := start
	// Optional "-end"; regex backtracking only matters when it fails, and
	// then the remaining text must be whitespace.
	save := i
	skip()
	if i < len(rs) && rs[i] == '-' {
		i++
		skip()
		if e, ok := number(); ok {
			end = e
		} else {
			i = save
		}
	} else {
		i = save
	}
	skip()
	if i != len(rs) {
		return 0, 0, false
	}
	return start, end, true
}

// FormatPorts mirrors ", ".join(a or a-b).
func FormatPorts(ranges [][2]int) string {
	parts := make([]string, len(ranges))
	for i, r := range ranges {
		if r[0] == r[1] {
			parts[i] = strconv.Itoa(r[0])
		} else {
			parts[i] = fmt.Sprintf("%d-%d", r[0], r[1])
		}
	}
	return strings.Join(parts, ", ")
}

var singleLabelSuffixes = map[string]bool{"phub": true, "internal": true}

func validSuffix(value string) (string, error) {
	value = strings.TrimRight(PyLower(PyStrip(value)), ".")
	// A single label would capture a whole top-level domain on every
	// enrolled machine (e.g. "com"), so only private-use labels qualify.
	if !strings.Contains(value, ".") && !singleLabelSuffixes[value] {
		return "", errors.New("Use phub, internal, or a full domain you own such as lan.example.com")
	}
	for _, part := range strings.Split(value, ".") {
		if !dnsLabel(part, 63) {
			return "", errors.New("Enter a domain suffix such as phub")
		}
	}
	if value == "localhost" || value == "local" || strings.HasSuffix(value, ".localhost") || strings.HasSuffix(value, ".local") {
		return "", errors.New("This suffix is reserved for local OS networking")
	}
	return value, nil
}

// dnsLabel matches [a-z0-9](?:[a-z0-9-]{0,max-2}[a-z0-9])? in full.
func dnsLabel(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && (c != '-' || i == 0 || i == len(s)-1) {
			return false
		}
	}
	return true
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func privateIPv4(value string) (string, error) {
	network, v4, ok := ipNetwork(value)
	if !ok {
		return "", errors.New("Enter a network CIDR such as 10.203.0.0/24")
	}
	inside := false
	for _, parent := range privateRanges {
		if v4 && parent.Bits() <= network.Bits() && parent.Contains(network.Addr()) {
			inside = true
		}
	}
	if !v4 || network.Bits() < 16 || network.Bits() > 28 || !inside {
		return "", errors.New("Choose an RFC1918 IPv4 range between /16 and /28")
	}
	return network.String(), nil
}

// ipNetwork mirrors ipaddress.ip_network(value, strict=True).
func ipNetwork(value string) (netip.Prefix, bool, bool) {
	if p, ok := ipv4Network(value); ok {
		return p, true, true
	}
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return netip.Prefix{}, false, false
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil || !addr.Is6() {
		return netip.Prefix{}, false, false
	}
	bits := 128
	if len(parts) == 2 {
		n, ok := asciiInt(parts[1])
		if !ok || n > 128 {
			return netip.Prefix{}, false, false
		}
		bits = n
	}
	p := netip.PrefixFrom(addr.WithZone(""), bits)
	if p.Masked().Addr() != addr.WithZone("") {
		return netip.Prefix{}, false, false
	}
	return p, false, true
}

func asciiInt(s string) (int, bool) {
	if s == "" || len(s) > 6 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func ipv4Addr(s string) (uint32, bool) {
	octets := strings.Split(s, ".")
	if len(octets) != 4 {
		return 0, false
	}
	var v uint32
	for _, o := range octets {
		n, ok := asciiInt(o)
		if !ok || len(o) > 3 || n > 255 || (len(o) > 1 && o[0] == '0') {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

func ipv4Network(value string) (netip.Prefix, bool) {
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return netip.Prefix{}, false
	}
	addr, ok := ipv4Addr(parts[0])
	if !ok {
		return netip.Prefix{}, false
	}
	bits := 32
	if len(parts) == 2 {
		if n, ok := asciiInt(parts[1]); ok && n <= 32 {
			bits = n
		} else if mask, ok := ipv4Addr(parts[1]); ok {
			if b, ok := contiguous(mask); ok {
				bits = b
			} else if b, ok := contiguous(^mask); ok { // hostmask
				bits = b
			} else {
				return netip.Prefix{}, false
			}
		} else {
			return netip.Prefix{}, false
		}
	}
	a := netip.AddrFrom4([4]byte{byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr)})
	p := netip.PrefixFrom(a, bits)
	if p.Masked().Addr() != a {
		return netip.Prefix{}, false
	}
	return p, true
}

// contiguous returns the prefix length of a netmask of leading ones.
func contiguous(mask uint32) (int, bool) {
	bits := 0
	for bits < 32 && mask&(1<<(31-bits)) != 0 {
		bits++
	}
	if bits < 32 && mask<<bits != 0 {
		return 0, false
	}
	return bits, true
}

// EntityMatches mirrors entity_matches.
func EntityMatches(s Selector, machine map[string]any, groups map[string]map[string]any) bool {
	switch s.Kind {
	case "all":
		return true
	case "machine":
		return PyStr(machine["_id"]) == s.ID
	}
	owner := ""
	if v := machine["private_owner_id"]; Truthy(v) {
		owner = PyStr(v)
	} else if v := machine["user_id"]; Truthy(v) {
		owner = PyStr(v)
	}
	if s.Kind == "user" {
		return owner == s.ID
	}
	group, ok := groups[s.ID]
	if s.Kind != "group" || !ok || group == nil {
		return false
	}
	var ids []any
	if v := machine["group_ids"]; Truthy(v) {
		ids, _ = asList(v)
	} else if Truthy(machine["group_id"]) {
		ids = []any{machine["group_id"]}
	}
	for _, id := range ids {
		if PyStr(id) == s.ID {
			return true
		}
	}
	users, _ := asList(group["user_ids"])
	for _, uid := range users {
		if PyStr(uid) == owner {
			return true
		}
	}
	return false
}

// Decision is evaluate_access's result.
type Decision struct {
	Allowed bool    `json:"allowed"`
	RuleID  *string `json:"rule_id"`
	BookID  *string `json:"book_id"`
	Reason  string  `json:"reason"`
}

func isFalse(d map[string]any, key string) bool {
	b, ok := d[key].(bool)
	return ok && !b
}

func enabled(d map[string]any) bool {
	v, has := d["enabled"]
	return !has || Truthy(v)
}

func books(raw []map[string]any, groups map[string]map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, b := range raw {
		if _, ok := groups[PyStr(b["group_id"])]; enabled(b) && ok {
			out = append(out, b)
		}
	}
	return out
}

func rules(book map[string]any) []AccessRule {
	out := []AccessRule{}
	list, _ := asList(book["rules"])
	for _, raw := range list {
		if r, err := ParseAccessRule(raw); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// EvaluateAccess evaluates initiation only (replies are conntrack's job).
// Allow-only policies combine by union; anything missing fails closed.
func EvaluateAccess(source, destination map[string]any, protocol string, port int, bookDocs []map[string]any, groups map[string]map[string]any) Decision {
	denied := Decision{Reason: "No enabled rule allows this connection"}
	if source == nil || destination == nil || isFalse(source, "enabled") || isFalse(destination, "enabled") ||
		Truthy(source["private_owner_revoked"]) || Truthy(destination["private_owner_revoked"]) {
		denied.Reason = "Both machines must be enabled"
		return denied
	}
	if PyStr(source["user_id"]) != PyStr(destination["user_id"]) {
		denied.Reason = "Machines belong to different workspaces"
		return denied
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		denied.Reason = "Unsupported protocol or invalid port"
		return denied
	}
	if (protocol == "tcp" || protocol == "udp") && (port < 1 || port > 65535) {
		denied.Reason = "Port is outside the supported range"
		return denied
	}
	for _, book := range books(bookDocs, groups) {
		if PyStr(book["user_id"]) != PyStr(source["user_id"]) {
			continue
		}
		for _, rule := range rules(book) {
			if !rule.Enabled || (rule.Protocol != "any" && rule.Protocol != protocol) {
				continue
			}
			ranges, _ := ParsePorts(rule.Ports)
			if len(ranges) > 0 && !inRanges(ranges, port) {
				continue
			}
			matches := func(left, right map[string]any) bool {
				return anyMatch(rule.Sources, left, groups) && anyMatch(rule.Destinations, right, groups)
			}
			if matches(source, destination) || (rule.Bidirectional && matches(destination, source)) {
				ruleID, bookID := rule.ID, PyStr(book["_id"])
				return Decision{Allowed: true, RuleID: &ruleID, BookID: &bookID, Reason: rule.Name}
			}
		}
	}
	return denied
}

func inRanges(ranges [][2]int, port int) bool {
	for _, r := range ranges {
		if r[0] <= port && port <= r[1] {
			return true
		}
	}
	return false
}

func anyMatch(selectors []Selector, machine map[string]any, groups map[string]map[string]any) bool {
	for _, s := range selectors {
		if EntityMatches(s, machine, groups) {
			return true
		}
	}
	return false
}
