package firewall

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// valErr is a pydantic v1 / FastAPI 0.79 validation item.
type valErr struct {
	Loc  []any          `json:"loc"`
	Msg  string         `json:"msg"`
	Type string         `json:"type"`
	Ctx  map[string]any `json:"ctx,omitempty"`
}

func invalid(items []valErr) error { return &httpapi.FastAPIError{Status: 422, Detail: items} }

func intErr(where, name string) valErr {
	return valErr{Loc: []any{where, name}, Msg: "value is not a valid integer", Type: "type_error.integer"}
}

var internalError = httpapi.Fail(500, "Internal Server Error")

type requestKey struct{}

func request(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

func writeDetail(ctx huma.Context, status int, detail any) {
	b, _ := json.Marshal(map[string]any{"detail": detail})
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetStatus(status)
	_, _ = ctx.BodyWriter().Write(b)
}

type policyData struct {
	Port       int64    `json:"port"`
	IsPublic   bool     `json:"is_public"`
	AllowedIPs []string `json:"allowed_ips"`
}

// serializePolicy is _serialize_policy; a missing policy is public.
func serializePolicy(port int64, p *Policy) policyData {
	if p == nil {
		return policyData{Port: port, IsPublic: true, AllowedIPs: []string{}}
	}
	return policyData{Port: port, IsPublic: p.IsPublic, AllowedIPs: append([]string{}, p.AllowedIPs...)}
}

type policyOut struct {
	Body struct {
		Msg  string     `json:"msg"`
		Data policyData `json:"data"`
	}
}

func policyResponse(msg string, d policyData) *policyOut {
	out := &policyOut{}
	out.Body.Msg, out.Body.Data = msg, d
	return out
}

type portPath struct {
	Port string `path:"port" doc:"Port number"`
}

// parsePort validates the {port} path parameter (int); ok=false with an
// overflow means a valid but out-of-range integer.
func parsePort(raw string) (port int64, errs []valErr, overflow bool) {
	n, ok, over := pyIntString(raw)
	if !ok {
		return 0, []valErr{intErr("path", "port")}, false
	}
	return n, nil, over
}

func checkPortRange(port int64, overflow bool) error {
	if overflow || port < 1 || port > 65535 {
		return httpapi.Fail(400, "Invalid port")
	}
	return nil
}

type policyBody struct {
	_          struct{} `json:"-" additionalProperties:"true"`
	IsPublic   *bool    `json:"is_public,omitempty" default:"true" example:"true"`
	AllowedIPs []string `json:"allowed_ips,omitempty" example:"[\"203.0.113.10\"]"`
}

type samplesOut struct {
	Body struct {
		Msg  string      `json:"msg"`
		Data portSamples `json:"data"`
	}
}

// Schema documents portSamples as {port: [sample]}.
func (portSamples) Schema(r huma.Registry) *huma.Schema {
	return &huma.Schema{Type: "object", AdditionalProperties: &huma.Schema{Type: "array",
		Items: r.Schema(reflectSample, true, "TrafficSample")}}
}

// register adds every firewall route to the API (router/ping.py and
// router/ports/*).
func (s *Service) register(api huma.API) {
	root := s.cfg.APIRoot
	tag := []string{"Ports"}
	auth := huma.Middlewares{func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		keys := r.Header.Values("X-Api-Key")
		if len(keys) == 0 {
			writeDetail(ctx, 422, []valErr{{Loc: []any{"header", "x-api-key"}, Msg: "field required", Type: "value_error.missing"}})
			return
		}
		if keys[0] != s.cfg.APIKey {
			writeDetail(ctx, 403, "Forbidden")
			return
		}
		next(ctx)
	}}
	// FastAPI 0.79 reports an empty body as a missing required field.
	withBody := append(huma.Middlewares{}, auth...)
	withBody = append(withBody, func(ctx huma.Context, next func(huma.Context)) {
		if r, _ := humago.Unwrap(ctx); r.ContentLength == 0 {
			writeDetail(ctx, 422, []valErr{{Loc: []any{"body"}, Msg: "field required", Type: "value_error.missing"}})
			return
		}
		next(ctx)
	})

	huma.Register(api, huma.Operation{OperationID: "ping", Method: http.MethodGet, Path: root + "/ping", Summary: "Ping"},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Msg     string `json:"msg"`
				Service string `json:"service"`
			}
		}, error) {
			out := &struct {
				Body struct {
					Msg     string `json:"msg"`
					Service string `json:"service"`
				}
			}{}
			out.Body.Msg, out.Body.Service = "pong", "firewall"
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-port-policy", Method: http.MethodGet, Path: root + "/ports/{port}/policy",
		Summary: "Get Port Policy", Tags: tag, Middlewares: auth},
		func(ctx context.Context, in *portPath) (*policyOut, error) {
			port, errs, overflow := parsePort(in.Port)
			if errs != nil {
				return nil, invalid(errs)
			}
			if err := checkPortRange(port, overflow); err != nil {
				return nil, err
			}
			s.polMu.Lock()
			defer s.polMu.Unlock()
			var p *Policy
			if v, ok := s.state[port]; ok {
				p = &v
			}
			return policyResponse("Port policy fetched successfully", serializePolicy(port, p)), nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-port-policy", Method: http.MethodPut, Path: root + "/ports/{port}/policy",
		Summary: "Update Port Policy", Tags: tag, Middlewares: withBody},
		func(ctx context.Context, in *struct {
			Port string `path:"port" doc:"Port number"`
			Body policyBody
		}) (*policyOut, error) {
			port, errs, overflow := parsePort(in.Port)
			isPublic := in.Body.IsPublic == nil || *in.Body.IsPublic
			ips := []string{}
			var bodyErrs []valErr
			for i, raw := range in.Body.AllowedIPs {
				addr, err := netip.ParseAddr(raw)
				if err != nil || !addr.Is4() {
					bodyErrs = append(bodyErrs, valErr{Loc: []any{"body", "allowed_ips", i}, Msg: "value is not a valid IPv4 address", Type: "value_error.ipv4address"})
					continue
				}
				ips = append(ips, addr.String())
			}
			if bodyErrs == nil && isPublic && len(ips) > 0 {
				bodyErrs = []valErr{{Loc: []any{"body", "__root__"}, Msg: "allowed_ips must be empty when is_public is true", Type: "value_error"}}
			}
			if errs = append(errs, bodyErrs...); errs != nil {
				return nil, invalid(errs)
			}
			if err := checkPortRange(port, overflow); err != nil {
				return nil, err
			}
			policy := Policy{IsPublic: isPublic, AllowedIPs: ips}
			s.polMu.Lock()
			defer s.polMu.Unlock()
			isPublicInt := 0
			if isPublic {
				isPublicInt = 1
			}
			if _, err := s.db.ExecContext(ctx, `
            INSERT OR REPLACE INTO port_policies (port, is_public, allowed_ips, updated_at)
            VALUES (?, ?, ?, ?)
            `, port, isPublicInt, pyDumps(ips), time.Now().Unix()); err != nil {
				log.Printf("firewall: store policy %d: %v", port, err)
				return nil, internalError
			}
			s.state[port] = policy
			if err := s.applyRules(s.state); err != nil {
				log.Printf("firewall: apply rules: %v", err)
				return nil, internalError
			}
			return policyResponse("Port policy updated successfully", serializePolicy(port, &policy)), nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-port-policy", Method: http.MethodDelete, Path: root + "/ports/{port}/policy",
		Summary: "Delete Port Policy", Tags: tag, Middlewares: auth},
		func(ctx context.Context, in *portPath) (*policyOut, error) {
			port, errs, overflow := parsePort(in.Port)
			if errs != nil {
				return nil, invalid(errs)
			}
			if err := checkPortRange(port, overflow); err != nil {
				return nil, err
			}
			s.polMu.Lock()
			defer s.polMu.Unlock()
			if _, err := s.db.ExecContext(ctx, "DELETE FROM port_policies WHERE port = ?", port); err != nil {
				log.Printf("firewall: delete policy %d: %v", port, err)
				return nil, internalError
			}
			delete(s.state, port)
			if err := s.applyRules(s.state); err != nil {
				log.Printf("firewall: apply rules: %v", err)
				return nil, internalError
			}
			return policyResponse("Port policy deleted successfully", serializePolicy(port, nil)), nil
		})

	type policiesOut struct {
		Body struct {
			Msg  string       `json:"msg"`
			Data []policyData `json:"data"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "list-port-policies", Method: http.MethodGet, Path: root + "/ports/policies/list",
		Summary: "List Port Policies", Tags: tag, Middlewares: auth},
		func(ctx context.Context, _ *struct{}) (*policiesOut, error) {
			s.polMu.Lock()
			defer s.polMu.Unlock()
			out := &policiesOut{}
			out.Body.Msg = "Port policies listed successfully"
			out.Body.Data = []policyData{}
			for _, port := range sortedKeys(s.state) {
				p := s.state[port]
				out.Body.Data = append(out.Body.Data, serializePolicy(port, &p))
			}
			return out, nil
		})

	type activePort struct {
		Port     int64 `json:"port"`
		LastSeen int64 `json:"last_seen"`
	}
	type activeOut struct {
		Body struct {
			Msg  string       `json:"msg"`
			Data []activePort `json:"data"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "active-ports", Method: http.MethodGet, Path: root + "/ports/active",
		Summary: "Active Ports", Tags: tag, Middlewares: auth},
		func(ctx context.Context, _ *struct{}) (*activeOut, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			out := &activeOut{}
			out.Body.Msg = "Active ports listed successfully"
			out.Body.Data = []activePort{}
			for _, port := range sortedKeys(s.active) {
				out.Body.Data = append(out.Body.Data, activePort{Port: port, LastSeen: s.active[port]})
			}
			return out, nil
		})

	type hitsOut struct {
		Body struct {
			Msg  string  `json:"msg"`
			Data []ipHit `json:"data"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "recent-ip-hits", Method: http.MethodGet, Path: root + "/ports/{port}/recent-ip-hits",
		Summary: "Get Recent Ip Hits", Tags: tag, Middlewares: auth},
		func(ctx context.Context, in *struct {
			Port  string `path:"port" doc:"Port number"`
			Limit string `query:"limit" doc:"1 to 50, default 10"`
		}) (*hitsOut, error) {
			port, errs, overflow := parsePort(in.Port)
			limit := int64(10)
			if q := request(ctx).URL.Query()["limit"]; len(q) > 0 {
				n, ok, _ := pyIntString(q[len(q)-1]) // overflow is clamped
				switch {
				case !ok:
					errs = append(errs, intErr("query", "limit"))
				case n > 50:
					errs = append(errs, valErr{Loc: []any{"query", "limit"}, Msg: "ensure this value is less than or equal to 50",
						Type: "value_error.number.not_le", Ctx: map[string]any{"limit_value": 50}})
				case n < 1:
					errs = append(errs, valErr{Loc: []any{"query", "limit"}, Msg: "ensure this value is greater than or equal to 1",
						Type: "value_error.number.not_ge", Ctx: map[string]any{"limit_value": 1}})
				default:
					limit = n
				}
			}
			if errs != nil {
				return nil, invalid(errs)
			}
			if overflow { // Python: int too large for SQLite
				return nil, internalError
			}
			hits, err := s.recentHits(ctx, port, limit)
			if err != nil {
				log.Printf("firewall: recent ip hits %d: %v", port, err)
				return nil, internalError
			}
			out := &hitsOut{}
			out.Body.Msg, out.Body.Data = "Recent IP hits fetched successfully", hits
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "traffic-snapshot", Method: http.MethodPost, Path: root + "/ports/traffic/snapshot",
		Summary: "Snapshot", Tags: tag, Middlewares: withBody},
		func(ctx context.Context, in *struct {
			Body struct {
				_     struct{} `json:"-" additionalProperties:"true"`
				Ports []int64  `json:"ports,omitempty" example:"[2334,8080]"`
			}
		}) (*samplesOut, error) {
			out := &samplesOut{}
			out.Body.Msg = "Traffic snapshot fetched successfully"
			out.Body.Data = s.snapshotData(in.Body.Ports, time.Now().Unix())
			return out, nil
		})
}

// recentHits stores the live set members, trims the history and reads it
// back (get_recent_ip_hits).
func (s *Service) recentHits(ctx context.Context, port, limit int64) ([]ipHit, error) {
	live := s.liveHits("recent_" + itoa(port))
	if len(live) > 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		for _, h := range live {
			if _, err := tx.ExecContext(ctx, upsertRecentSQL, port, h.IP, h.LastSeen); err != nil {
				return nil, err
			}
		}
		if err := s.trimRecentIPHistory(ctx, tx, port); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	rows, err := s.db.QueryContext(ctx, `
            SELECT ip, last_seen
            FROM recent_ip_hits
            WHERE port = ?
            ORDER BY last_seen DESC, ip ASC
            LIMIT ?
            `, port, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := []ipHit{}
	for rows.Next() {
		var h ipHit
		if err := rows.Scan(&h.IP, &h.LastSeen); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

var reflectSample = reflect.TypeOf(sample{})

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func sortedKeys[V any](m map[int64]V) []int64 {
	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
