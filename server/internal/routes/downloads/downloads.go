// Package downloads serves the prebuilt PortHub client binaries bundled in
// the server image, for every supported platform, without a machine token.
package downloads

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
)

// Targets maps a download target to its GOOS/GOARCH description.
var Targets = []struct{ Name, OS, Arch string }{
	{"x86_64", "linux", "amd64"},
	{"arm64", "linux", "arm64"},
	{"armv7", "linux", "armv7"},
	{"armhf", "linux", "armv6"},
	{"darwin_x86_64", "darwin", "amd64"},
	{"darwin_arm64", "darwin", "arm64"},
}

func version(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "porthub-"+name+".version"))
	return strings.TrimSpace(string(b))
}

func Register(api huma.API, app *core.App) {
	huma.Register(api, huma.Operation{OperationID: "list-client-downloads", Method: http.MethodGet, Path: "/api/downloads/porthub",
		Summary: "List PortHub client binaries", Tags: []string{"Downloads"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body map[string]any }, error) {
			r := httpapi.Request(ctx)
			base := app.PublicBaseURL(r) + "/api/downloads/porthub/"
			items := []any{}
			for _, t := range Targets {
				info, err := os.Stat(filepath.Join(app.Cfg.ClientBinaryDir, "porthub-"+t.Name))
				if err != nil {
					continue
				}
				items = append(items, map[string]any{"target": t.Name, "os": t.OS, "arch": t.Arch, "size": info.Size(),
					"version": version(app.Cfg.ClientBinaryDir, t.Name), "url": base + t.Name})
			}
			return &struct{ Body map[string]any }{map[string]any{"data": items}}, nil
		})
}

// Mount adds the binary download itself (a raw file response).
func Mount(mux *http.ServeMux, app *core.App) {
	mux.HandleFunc("GET /api/downloads/porthub/{target}", func(w http.ResponseWriter, r *http.Request) {
		target := r.PathValue("target")
		known := false
		for _, t := range Targets {
			known = known || t.Name == target
		}
		path := filepath.Join(app.Cfg.ClientBinaryDir, "porthub-"+target)
		if _, err := os.Stat(path); !known || err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Unknown client target"}`))
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="porthub"`)
		w.Header().Set("X-PortHub-Version", version(app.Cfg.ClientBinaryDir, target))
		http.ServeFile(w, r, path)
	})
}
