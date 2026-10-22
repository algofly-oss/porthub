package machines

import (
	"context"
	"net/netip"
	"sort"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// privateIPs returns only this machine owner's enabled private enrollments.
func (h *h) privateIPs(ctx context.Context, machine core.Doc) ([]string, error) {
	ips := []string{}
	if core.Truthy(machine, "private_owner_revoked") {
		return ips, nil
	}
	peers, err := h.app.FindAll(ctx, "private_peers", bson.M{"machine_id": machine["_id"], "owner_id": machine["user_id"], "enabled": true})
	if err != nil {
		return nil, err
	}
	return privatePeerIPs(peers), nil
}

func privatePeerIPs(peers []core.Doc) []string {
	ips := []string{}
	seen := map[string]bool{}
	for _, p := range peers {
		ip, err := netip.ParseAddr(core.Str(p, "ip"))
		if err == nil && ip.Is4() && ip.IsPrivate() && !seen[ip.String()] {
			ips = append(ips, ip.String())
			seen[ip.String()] = true
		}
	}
	sort.Strings(ips)
	return ips
}

type privateAddressesIn struct {
	MachineID string `path:"machine_id"`
}

func (h *h) privateAddresses(ctx context.Context, in *privateAddressesIn) (*anyBody, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, err := core.ParseOID(in.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": id, "user_id": user["_id"], "deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(404, "Machine not found")
	}
	ips, err := h.privateIPs(ctx, machine)
	if err != nil {
		return nil, err
	}
	return body(map[string]any{"data": ips}), nil
}
