package machines

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// GET /machines/{machine_id}/status-history and GET /machines/command/{machine_id}
// both match /machines/command/status-history, which Go's ServeMux rejects
// as conflicting patterns. Both operations are documented as usual, but served
// through one /api/machines/{first}/{second} route that picks the handler in
// FastAPI's registration order (status history first).

type pairAPI struct {
	huma.API
	adapter *pairAdapter
}

func (p *pairAPI) Adapter() huma.Adapter { return p.adapter }

type pairHandler struct {
	op      *huma.Operation
	handler func(huma.Context)
}

type pairAdapter struct {
	huma.Adapter
	handlers map[string]pairHandler // by operation path
}

func (a *pairAdapter) Handle(op *huma.Operation, handler func(huma.Context)) {
	a.handlers[op.Path] = pairHandler{op, handler}
}

const (
	statusHistoryPath = "/api/machines/{machine_id}/status-history"
	commandPath       = "/api/machines/command/{machine_id}"
)

func newPairAPI(api huma.API) *pairAPI {
	return &pairAPI{API: api, adapter: &pairAdapter{Adapter: api.Adapter(), handlers: map[string]pairHandler{}}}
}

// mount registers the shared route on the real adapter.
func (p *pairAPI) mount() {
	handlers := p.adapter.handlers
	p.adapter.Adapter.Handle(&huma.Operation{Method: http.MethodGet, Path: "/api/machines/{first}/{second}"}, func(ctx huma.Context) {
		r, w := humago.Unwrap(ctx)
		first, second := r.PathValue("first"), r.PathValue("second")
		var h pairHandler
		switch {
		case second == "status-history":
			h = handlers[statusHistoryPath]
			r.SetPathValue("machine_id", first)
		case first == "command":
			h = handlers[commandPath]
			r.SetPathValue("machine_id", second)
		default:
			notFound(w)
			return
		}
		h.handler(humago.NewContext(h.op, r, w))
	})
}

// notFound is Starlette's 404 for unmatched routes.
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
}

// jsonBytes encodes like Starlette's JSONResponse (no HTML escaping).
func jsonBytes(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// rawOut is a response written as-is: exact status, headers (empty values
// included, as Starlette sends them) and body.
type rawOut struct {
	Body func(huma.Context)
}

type header struct{ name, value string }

func raw(status int, headers []header, body []byte) *rawOut {
	return &rawOut{Body: func(ctx huma.Context) {
		for _, h := range headers {
			ctx.SetHeader(h.name, h.value)
		}
		ctx.SetStatus(status)
		if len(body) > 0 {
			_, _ = ctx.BodyWriter().Write(body)
		}
	}}
}

const textPlain = "text/plain; charset=utf-8"
