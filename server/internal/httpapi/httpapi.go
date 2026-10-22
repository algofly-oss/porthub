// Package httpapi wires the Go API, compatible error responses, request
// context, OpenAPI documentation and Swagger UI.
package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

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
	API huma.API
	Mux *http.ServeMux
}

// New builds the standalone Go API. Unknown routes return a JSON 404.
func New() (*Server, error) {
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("PortHub API", "0.2.0")
	cfg.OpenAPIPath = "/api/openapi"
	cfg.DocsPath = ""
	cfg.SchemasPath = "/api/schemas"
	cfg.CreateHooks = nil // no "$schema" links in bodies: keep FastAPI's exact responses
	cfg.Info.Description = "PortHub server API."
	// Route packages intentionally reuse local type names (e.g. deleteBody).
	// Include their package in schema names so the assembled API stays unique.
	cfg.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", func(t reflect.Type, hint string) string {
		name := huma.DefaultSchemaNamer(t, hint)
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if pkg := t.PkgPath(); pkg != "" {
			pkg = strings.TrimPrefix(pkg, "github.com/algofly-oss/porthub/server/internal/")
			return strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(pkg) + "_" + name
		}
		return name
	})
	api := humago.New(mux, cfg)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		next(huma.WithValue(ctx, requestKey{}, r))
	})
	s := &Server{API: api, Mux: mux}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
	})
	mux.HandleFunc("GET /api", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/docs", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("GET /api/openapi-go.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/openapi.json", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("GET /api/docs", swaggerUI)
	return s, nil
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
