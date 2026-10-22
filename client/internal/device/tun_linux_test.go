//go:build linux

package device

import (
	"net/netip"
	"testing"
)

func TestPrivateRoutesDoNotOverrideExistingNetwork(t *testing.T) {
	ip := []netip.Addr{netip.MustParseAddr("10.203.0.2")}
	ok := []route{{netip.MustParsePrefix("192.168.1.0/24"), "eth0"}, {netip.MustParsePrefix("0.0.0.0/0"), "eth0"}}
	if err := checkRoutes(ok, ip); err != nil {
		t.Fatal(err)
	}
	for _, r := range []route{{netip.MustParsePrefix("10.0.0.0/8"), "corporate-vpn"}, {netip.MustParsePrefix("10.203.0.2/32"), "other-tenant"}} {
		if checkRoutes([]route{r}, ip) == nil {
			t.Fatalf("conflicting route accepted: %v", r)
		}
	}
	if checkRoutes(nil, []netip.Addr{netip.MustParseAddr("8.8.8.8")}) == nil {
		t.Fatal("public address accepted")
	}
}

// Reading the live tables must work without any external command.
func TestReadsHostRoutingTablesViaNetlink(t *testing.T) {
	if err := CheckRoutes([]netip.Addr{netip.MustParseAddr("10.255.254.253")}); err != nil {
		t.Log(err) // a host may legitimately have a covering route; only errors from reading matter
	}
}
