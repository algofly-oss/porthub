package firewall

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Policy is one port's stored firewall policy (STATE[str(port)]).
type Policy struct {
	IsPublic   bool
	AllowedIPs []string
}

// BuildRules renders the nftables ruleset exactly like shared/nft.py.
func BuildRules(state map[int64]Policy, table string, recentTTL int64) string {
	var sets, counters []string
	input := []string{"        type filter hook input priority 0;"}
	output := []string{"        type filter hook output priority 0;"}
	ports := make([]int64, 0, len(state))
	for p := range state {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	ttl := fmt.Sprintf("%ds", recentTTL)
	for _, port := range ports {
		allowed := state[port].AllowedIPs
		p := fmt.Sprint(port)
		counters = append(counters,
			"    counter cnt_in_"+p+" {}",
			"    counter cnt_out_"+p+" {}",
			"    counter cnt_drop_"+p+" {}",
			"")
		for _, name := range []string{"recent_" + p, "recent_out_" + p} {
			sets = append(sets,
				"    set "+name+" {",
				"        type ipv4_addr;",
				"        flags dynamic, timeout;",
				"        timeout "+ttl+";",
				"    }",
				"")
		}
		recent := "        tcp dport " + p + " ct state new update @recent_" + p + " { ip saddr timeout " + ttl + " }"
		if len(allowed) > 0 {
			sets = append(sets,
				"    set allow_"+p+" {",
				"        type ipv4_addr;",
				"        elements = { "+strings.Join(allowed, ", ")+" }",
				"    }",
				"",
				"    set blocked_"+p+" {",
				"        type ipv4_addr;",
				"        flags dynamic, timeout;",
				"        timeout "+ttl+";",
				"    }",
				"")
			input = append(input,
				recent,
				"        tcp dport "+p+" ip saddr @allow_"+p+` counter name "cnt_in_`+p+`" accept`,
				"        tcp dport "+p+" ct state new update @blocked_"+p+" { ip saddr timeout "+ttl+` } counter name "cnt_drop_`+p+`" drop`)
		} else {
			input = append(input,
				recent,
				"        tcp dport "+p+` counter name "cnt_in_`+p+`" accept`)
		}
		output = append(output,
			"        tcp sport "+p+" update @recent_out_"+p+" { ip daddr timeout "+ttl+` } counter name "cnt_out_`+p+`" accept`)
	}
	lines := []string{"table " + table + " {"}
	lines = append(lines, counters...)
	lines = append(lines, sets...)
	lines = append(lines, "    chain input {")
	lines = append(lines, input...)
	lines = append(lines, "    }", "", "    chain output {")
	lines = append(lines, output...)
	lines = append(lines, "    }", "}")
	return strings.Join(lines, "\n") + "\n"
}

// runNFT runs nft; nil writers discard. Tests replace it.
var runNFT = func(stdin []byte, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command("nft", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// nftOutput is subprocess.check_output(["nft", ...]).
func nftOutput(stderr io.Writer, args ...string) ([]byte, error) {
	var out bytes.Buffer
	err := runNFT(nil, &out, stderr, args...)
	return out.Bytes(), err
}

// applyRules deletes the table (errors ignored) and loads the new ruleset
// with `nft -f -`, like apply_rules.
func (s *Service) applyRules(state map[int64]Policy) error {
	_ = runNFT(nil, nil, nil, append([]string{"delete", "table"}, strings.Fields(s.cfg.NFTTable)...)...)
	rules := BuildRules(state, s.cfg.NFTTable, s.cfg.RecentIPTTL)
	if err := runNFT([]byte(rules), os.Stdout, os.Stderr, "-f", "-"); err != nil {
		return fmt.Errorf("nft -f -: %w", err)
	}
	return nil
}
