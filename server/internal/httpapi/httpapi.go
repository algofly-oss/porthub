// Package httpapi wires the Go API: FastAPI-compatible errors, the request
// in the operation context, Swagger UI with one merged OpenAPI document, and
// a pass-through to the Python API for routes not yet ported.
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// FastAPIError matches FastAPI's {"detail": ...} error body, which the web
// app and installed clients parse.
type FastAPIError struct {
	Status int `json:"-"`
	Detail any `json:"detail"`
}

func (e *FastAPIError) Error() string  { return fmt.Sprint(e.Detail) }
func (e *FastAPIError) GetStatus() int { return e.Status }

// Validation error item in FastAPI's format.
type validationItem struct {
	Loc  []string `json:"loc"`
	Msg  string   `json:"msg"`
	Type string   `json:"type"`
}

func init() {
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		if status == http.StatusUnprocessableEntity || (status == http.StatusBadRequest && len(errs) > 0) {
			items := []validationItem{}
			for _, err := range errs {
				items = append(items, fastAPIValidation(err))
			}
			return &FastAPIError{Status: http.StatusUnprocessableEntity, Detail: items}
		}
		return &FastAPIError{Status: status, Detail: msg}
	}
}

// Fail returns a FastAPI-style error (HTTPException(status, detail)).
func Fail(status int, detail string) error { return &FastAPIError{Status: status, Detail: detail} }

type requestKey struct{}

// Request returns the incoming HTTP request of an operation.
func Request(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

type Server struct {
	API    huma.API
	Mux    *http.ServeMux
	python *url.URL
}

func New(pythonAPI string) (*Server, error) {
	target, err := url.Parse(pythonAPI)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("PortHub API", "0.2.0")
	cfg.OpenAPIPath = "/api/openapi-go" // merged document is served at /api/openapi.json
	cfg.DocsPath = ""
	cfg.SchemasPath = "/api/schemas"
	cfg.CreateHooks = nil // no "$schema" links in bodies: keep FastAPI's exact responses
	cfg.Info.Description = "PortHub server API. Routes are served by the Go API; any route not yet ported is answered by the previous Python API transparently."
	api := humago.New(mux, cfg)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		next(huma.WithValue(ctx, requestKey{}, r))
	})
	s := &Server{API: api, Mux: mux, python: target}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1 // stream long polls and log streams immediately
	mux.Handle("/", proxy)
	mux.HandleFunc("GET /api/openapi.json", s.openAPI)
	mux.HandleFunc("GET /api/docs", swaggerUI)
	return s, nil
}

// openAPI merges the Go document with the Python one, so Swagger UI lists
// the whole API while routes move over.
func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	goDoc, err := json.Marshal(s.API.OpenAPI())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var merged map[string]any
	_ = json.Unmarshal(goDoc, &merged)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.python.String()+"/api/openapi.json", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		var py map[string]any
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if json.Unmarshal(body, &py) == nil {
			mergeMaps(merged, py, "paths")
			if pc, ok := py["components"].(map[string]any); ok {
				if mc, ok := merged["components"].(map[string]any); ok {
					mergeMaps(mc, pc, "schemas")
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(merged)
}

// mergeMaps adds entries of src[key] missing from dst[key] (path methods and
// schema names already defined in Go win).
func mergeMaps(dst, src map[string]any, key string) {
	d, _ := dst[key].(map[string]any)
	if d == nil {
		d = map[string]any{}
		dst[key] = d
	}
	sm, _ := src[key].(map[string]any)
	for name, value := range sm {
		existing, ok := d[name].(map[string]any)
		incoming, isMap := value.(map[string]any)
		if !ok {
			d[name] = value
			continue
		}
		if key == "paths" && isMap {
			for method, op := range incoming {
				if _, has := existing[method]; !has {
					existing[method] = op
				}
			}
		}
	}
}

func swaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>PortHub API - Swagger UI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/api/openapi.json",dom_id:"#swagger-ui",defaultModelsExpandDepth:-1,persistAuthorization:true});</script>
</body></html>`)
}

var requiredRE = regexp.MustCompile(`^expected required property (\S+) to be present$`)

// fastAPIValidation renders a huma validation detail like pydantic v1 /
// FastAPI 0.79 do: loc ["body", field], "field required", "value_error.missing".
func fastAPIValidation(err error) validationItem {
	item := validationItem{Msg: err.Error(), Type: "value_error"}
	d, ok := err.(huma.ErrorDetailer)
	if !ok {
		return item
	}
	detail := d.ErrorDetail()
	item.Msg = detail.Message
	item.Loc = strings.Split(detail.Location, ".")
	if m := requiredRE.FindStringSubmatch(detail.Message); m != nil {
		item.Loc = append(item.Loc, m[1])
		item.Msg, item.Type = "field required", "value_error.missing"
	} else if strings.HasPrefix(detail.Message, "expected string") {
		item.Msg, item.Type = "str type expected", "type_error.str"
	} else if strings.HasPrefix(detail.Message, "expected boolean") {
		item.Msg, item.Type = "value could not be parsed to a boolean", "type_error.bool"
	} else if strings.HasPrefix(detail.Message, "expected integer") || strings.HasPrefix(detail.Message, "expected number") {
		item.Msg, item.Type = "value is not a valid integer", "type_error.integer"
	}
	return item
}
