package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FirewallError mirrors FirewallClientError.
type FirewallError struct{ Detail string }

func (e *FirewallError) Error() string { return e.Detail }

// FirewallConfigured mirrors is_firewall_configured.
func (a *App) FirewallConfigured() bool {
	return a.Cfg.FirewallBaseURL != "" && a.Cfg.FirewallAPIKey != ""
}

func (a *App) firewall(ctx context.Context, method, path string, body any) (map[string]any, error) {
	if !a.FirewallConfigured() {
		return nil, &FirewallError{"Firewall integration is not configured"}
	}
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, a.Cfg.FirewallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.Cfg.FirewallBaseURL+path, reader)
	if err != nil {
		return nil, &FirewallError{"Firewall request failed: " + err.Error()}
	}
	req.Header.Set("x-api-key", a.Cfg.FirewallAPIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &FirewallError{"Firewall request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	payload := map[string]any{}
	if json.Unmarshal(raw, &payload) != nil {
		payload = map[string]any{"detail": string(raw)}
	}
	if resp.StatusCode >= 400 {
		detail := payload["detail"]
		if !truthy(detail) {
			detail = payload["msg"]
		}
		if !truthy(detail) {
			detail = "Firewall request failed"
		}
		if s, ok := detail.(string); ok {
			return nil, &FirewallError{s}
		}
		b, _ := json.Marshal(detail)
		return nil, &FirewallError{string(b)}
	}
	return payload, nil
}

func dataMap(p map[string]any) map[string]any {
	if m, ok := p["data"].(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func dataList(p map[string]any) []any {
	if l, ok := p["data"].([]any); ok {
		return l
	}
	return []any{}
}

func (a *App) GetPortPolicy(ctx context.Context, port int) (map[string]any, error) {
	p, err := a.firewall(ctx, "GET", fmt.Sprintf("/ports/%d/policy", port), nil)
	if err != nil {
		return nil, err
	}
	return dataMap(p), nil
}

func (a *App) UpdatePortPolicy(ctx context.Context, port int, public bool, allowedIPs []any) (map[string]any, error) {
	if allowedIPs == nil {
		allowedIPs = []any{}
	}
	p, err := a.firewall(ctx, "PUT", fmt.Sprintf("/ports/%d/policy", port), map[string]any{"is_public": public, "allowed_ips": allowedIPs})
	if err != nil {
		return nil, err
	}
	return dataMap(p), nil
}

func (a *App) DeletePortPolicy(ctx context.Context, port int) (map[string]any, error) {
	p, err := a.firewall(ctx, "DELETE", fmt.Sprintf("/ports/%d/policy", port), nil)
	if err != nil {
		return nil, err
	}
	return dataMap(p), nil
}

func (a *App) ListActivePorts(ctx context.Context) ([]any, error) {
	p, err := a.firewall(ctx, "GET", "/ports/active", nil)
	if err != nil {
		return nil, err
	}
	return dataList(p), nil
}

func (a *App) TrafficSnapshot(ctx context.Context, ports []int) (map[string]any, error) {
	if ports == nil {
		ports = []int{}
	}
	p, err := a.firewall(ctx, "POST", "/ports/traffic/snapshot", map[string]any{"ports": ports})
	if err != nil {
		return nil, err
	}
	return dataMap(p), nil
}

func (a *App) RecentIPHits(ctx context.Context, port, limit int) ([]any, error) {
	p, err := a.firewall(ctx, "GET", fmt.Sprintf("/ports/%d/recent-ip-hits?limit=%d", port, limit), nil)
	if err != nil {
		return nil, err
	}
	return dataList(p), nil
}

func (a *App) DeletePortPolicyBestEffort(ctx context.Context, port int) {
	if !a.FirewallConfigured() {
		return
	}
	if _, err := a.DeletePortPolicy(ctx, port); err != nil {
		log.Printf("Failed to delete firewall policy for port %d: %v", port, err)
	}
}

// SyncConnectionFirewall mirrors sync_connection_firewall_policy.
func (a *App) SyncConnectionFirewall(ctx context.Context, connection Doc) {
	if !a.FirewallConfigured() {
		return
	}
	port, ok := Int(connection, "external_port")
	if !ok {
		return
	}
	if IsFalse(connection, "enabled") {
		a.DeletePortPolicyBestEffort(ctx, port)
		return
	}
	policy := FirewallPolicy(connection)
	if _, err := a.UpdatePortPolicy(ctx, port, policy["is_public"].(bool), policy["allowed_ips"].([]any)); err != nil {
		log.Printf("Failed to sync firewall policy for port %d: %v", port, err)
	}
}

func (a *App) SyncMachineFirewall(ctx context.Context, machineID any) error {
	connections, err := a.FindAll(ctx, "connections", bson.M{"machine_id": machineID})
	if err != nil {
		return err
	}
	for _, c := range connections {
		a.SyncConnectionFirewall(ctx, c)
	}
	return nil
}

func (a *App) DeleteMachineFirewall(ctx context.Context, machineID any) error {
	connections, err := a.FindAll(ctx, "connections", bson.M{"machine_id": machineID})
	if err != nil {
		return err
	}
	for _, c := range connections {
		if port, ok := Int(c, "external_port"); ok {
			a.DeletePortPolicyBestEffort(ctx, port)
		}
	}
	return nil
}

// ReconcileFirewall mirrors reconcile_firewall_state_from_db.
func (a *App) ReconcileFirewall(ctx context.Context) error {
	if !a.FirewallConfigured() {
		return nil
	}
	machines, err := a.FindAll(ctx, "machines", bson.M{})
	if err != nil {
		return err
	}
	byID := map[any]Doc{}
	for _, m := range machines {
		byID[m["_id"]] = m
	}
	connections, err := a.FindAll(ctx, "connections", bson.M{})
	if err != nil {
		return err
	}
	for _, c := range connections {
		machine := byID[c["machine_id"]]
		if machine == nil || IsFalse(machine, "enabled") {
			if port, ok := Int(c, "external_port"); ok {
				a.DeletePortPolicyBestEffort(ctx, port)
			}
			continue
		}
		a.SyncConnectionFirewall(ctx, c)
	}
	return nil
}

// IsFirewallError reports a FirewallClientError.
func IsFirewallError(err error) (*FirewallError, bool) {
	var fe *FirewallError
	ok := errors.As(err, &fe)
	return fe, ok
}
