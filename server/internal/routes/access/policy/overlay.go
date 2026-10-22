package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Private-only address allocation and policy compilation. Nothing public
// (ports, proxies, Rathole, firewall) is written by this logic.

// Fingerprint is a SHA-256 certificate fingerprint (FINGERPRINT).
var Fingerprint = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)

// Hostname is a custom private name label (HOSTNAME).
var Hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// ErrRangeFull is private_address's ValueError.
var ErrRangeFull = errors.New("The private address range is full")

// PrivateAddress mirrors private_address: a stable sha256-derived start
// inside the network, then the first free host address after it.
func PrivateAddress(cidr, machineID string, occupied map[string]bool) (string, error) {
	network, v4, ok := ipNetwork(cidr)
	if !ok {
		return "", errors.New("invalid network")
	}
	size := 32
	if !v4 {
		size = 128
	}
	total := new(big.Int).Lsh(big.NewInt(1), uint(size-network.Bits()))
	hosts := new(big.Int).Sub(total, big.NewInt(2))
	if hosts.Sign() < 0 { // /32: Python's range(-1) is empty
		return "", ErrRangeFull
	}
	if hosts.Sign() == 0 { // /31: Python raises ZeroDivisionError
		return "", errors.New("integer division or modulo by zero")
	}
	sum := sha256.Sum256([]byte(machineID))
	start := new(big.Int).SetUint64(binary.BigEndian.Uint64(sum[:8]))
	start.Mod(start, hosts)
	base := new(big.Int).SetBytes(network.Addr().AsSlice())
	offset := new(big.Int)
	one := big.NewInt(1)
	for offset.Cmp(hosts) < 0 {
		n := new(big.Int).Add(start, offset)
		n.Mod(n, hosts)
		n.Add(n, base).Add(n, one)
		buf := make([]byte, size/8)
		n.FillBytes(buf)
		addr, _ := netip.AddrFromSlice(buf)
		if s := addr.String(); !occupied[s] {
			return s, nil
		}
		offset.Add(offset, one)
	}
	return "", ErrRangeFull
}

// Grant is an explicit machine-pair permission for client ACLs.
type Grant struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Ports       []Port `json:"ports"`
}

type Port struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// CompileGrants mirrors compile_grants: named selectors become machine pairs,
// in first-seen order, so clients never learn other members' details.
func CompileGrants(machines, bookDocs []map[string]any, groups map[string]map[string]any) []Grant {
	active := []map[string]any{}
	for _, m := range machines {
		if enabled(m) && !Truthy(m["private_owner_revoked"]) {
			active = append(active, m)
		}
	}
	index := map[string]int{}
	grants := []Grant{}
	for _, book := range books(bookDocs, groups) {
		owner := PyStr(book["user_id"])
		for _, rule := range rules(book) {
			if !rule.Enabled {
				continue
			}
			pick := func(selectors []Selector) []map[string]any {
				out := []map[string]any{}
				for _, m := range active {
					if PyStr(m["user_id"]) == owner && anyMatch(selectors, m, groups) {
						out = append(out, m)
					}
				}
				return out
			}
			sources, destinations := pick(rule.Sources), pick(rule.Destinations)
			ranges, _ := ParsePorts(rule.Ports)
			ports := make([]Port, len(ranges))
			for i, r := range ranges {
				ports[i] = Port{r[0], r[1]}
			}
			portKey := FormatPorts(ranges)
			for _, source := range sources {
				for _, destination := range destinations {
					pairs := [][2]map[string]any{{source, destination}}
					if rule.Bidirectional {
						pairs = append(pairs, [2]map[string]any{destination, source})
					}
					for _, pair := range pairs {
						left, right := pair[0], pair[1]
						if Equal(left["_id"], right["_id"]) {
							continue
						}
						g := Grant{Source: PyStr(left["_id"]), Destination: PyStr(right["_id"]), Protocol: rule.Protocol, Ports: ports}
						key := g.Source + "\x00" + g.Destination + "\x00" + g.Protocol + "\x00" + portKey
						if i, ok := index[key]; ok {
							grants[i] = g
						} else {
							index[key] = len(grants)
							grants = append(grants, g)
						}
					}
				}
			}
		}
	}
	return grants
}

var nonLabel = regexp.MustCompile(`[^a-z0-9]+`)

// HostnameLabel mirrors hostname_label: the machine name as a DNS label.
func HostnameLabel(name any) string {
	s := ""
	if Truthy(name) {
		s = PyStr(name)
	}
	label := strings.Trim(nonLabel.ReplaceAllString(PyLower(s), "-"), "-")
	if r := []rune(label); len(r) > 48 {
		label = string(r[:48])
	}
	label = strings.Trim(label, "-")
	if label == "" {
		return "machine"
	}
	return label
}

// enrollment order: (str(created_at or ""), _id).
func enrollmentOrder(peers []map[string]any) []map[string]any {
	sorted := append([]map[string]any{}, peers...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := "", ""
		if Truthy(sorted[i]["created_at"]) {
			a = PyStr(sorted[i]["created_at"])
		}
		if Truthy(sorted[j]["created_at"]) {
			b = PyStr(sorted[j]["created_at"])
		}
		if a != b {
			return a < b
		}
		return PyStr(sorted[i]["_id"]) < PyStr(sorted[j]["_id"])
	})
	return sorted
}

func machineIndex(machines []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, m := range machines {
		out[Key(m["_id"])] = m
	}
	return out
}

// AssignHostnames mirrors assign_hostnames: {peer key: label}. Custom names
// win; others follow the machine name, a clash gets a machine-id suffix,
// earliest enrollment first. Keys are Key(peer["_id"]).
func AssignHostnames(machines, peers []map[string]any) map[string]string {
	names, taken := map[string]string{}, map[string]bool{}
	for _, peer := range peers {
		if Truthy(peer["hostname"]) {
			h := PyStr(peer["hostname"])
			names[Key(peer["_id"])] = h
			taken[h] = true
		}
	}
	byID := machineIndex(machines)
	for _, peer := range enrollmentOrder(peers) {
		if _, ok := names[Key(peer["_id"])]; ok {
			continue
		}
		var name any
		if m, ok := byID[Key(peer["machine_id"])]; ok {
			name = m["name"]
		}
		label := HostnameLabel(name)
		if taken[label] {
			short := label
			if r := []rune(short); len(r) > 43 {
				short = string(r[:43])
			}
			id := []rune(PyStr(peer["machine_id"]))
			if len(id) > 4 {
				id = id[len(id)-4:]
			}
			label = strings.TrimRight(short, "-") + "-" + string(id)
		}
		names[Key(peer["_id"])] = label
		taken[label] = true
	}
	return names
}

// AliasHostnames mirrors alias_hostnames: {peer key: [labels]}. An alias
// never takes a machine name, private name or an earlier peer's alias.
func AliasHostnames(machines, peers []map[string]any, primary map[string]string) map[string][]string {
	if primary == nil {
		primary = AssignHostnames(machines, peers)
	}
	taken := map[string]bool{}
	for _, label := range primary {
		taken[label] = true
	}
	for _, m := range machines {
		taken[HostnameLabel(m["name"])] = true
	}
	byID := machineIndex(machines)
	result := map[string][]string{}
	for _, peer := range enrollmentOrder(peers) {
		labels := []string{}
		if m, ok := byID[Key(peer["machine_id"])]; ok {
			aliases, _ := asList(m["aliases"])
			for _, alias := range aliases {
				label := HostnameLabel(alias)
				if !taken[label] {
					taken[label] = true
					labels = append(labels, label)
				}
			}
		}
		result[Key(peer["_id"])] = labels
	}
	return result
}

// HostnameConflict mirrors hostname_conflict: the name of the other machine
// owning label (Python None when that machine has no name), or found=false.
// Callers treat a falsy name as no conflict, like Python's `if clash:`.
func HostnameConflict(label string, machineID any, machines, peers []map[string]any) (any, bool) {
	for _, m := range machines {
		if Equal(m["_id"], machineID) {
			continue
		}
		names := []any{m["name"]}
		aliases, _ := asList(m["aliases"])
		names = append(names, aliases...)
		for _, n := range names {
			if HostnameLabel(n) == label {
				return m["name"], true
			}
		}
	}
	current := AssignHostnames(machines, peers)
	byID := machineIndex(machines)
	for _, peer := range peers {
		if !Equal(peer["machine_id"], machineID) && current[Key(peer["_id"])] == label {
			if m, ok := byID[Key(peer["machine_id"])]; ok {
				return m["name"], true
			}
			return "another machine", true
		}
	}
	return nil, false
}
