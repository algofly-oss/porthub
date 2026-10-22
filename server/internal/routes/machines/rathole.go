package machines

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/httpapi"
)

// Machines download the bundled PortHub Go client in place of Rathole: it is
// a drop-in Rathole client (`porthub -c client.toml`).

var clientTargets = map[string]bool{
	"x86_64": true, "arm64": true, "armhf": true, "armv7": true, "darwin_x86_64": true, "darwin_arm64": true,
}

var targetAliases = map[string]string{
	"amd64":        "x86_64",
	"x86":          "x86_64",
	"aarch64":      "arm64",
	"arm":          "armhf",
	"darwin_amd64": "darwin_x86_64",
}

// NormalizeTarget mirrors normalize_target.
func NormalizeTarget(target string) (string, error) {
	if alias, ok := targetAliases[target]; ok {
		target = alias
	}
	if !clientTargets[target] {
		return "", httpapi.Fail(404, "Unsupported Rathole target")
	}
	return target, nil
}

// clientBinary returns the bundled binary for a normalized target, its asset
// name and its version ("" when no .version file exists).
func clientBinary(dir, target string) (path, asset, version string, err error) {
	asset = "porthub-" + target
	path = filepath.Join(dir, asset)
	if info, statErr := os.Stat(path); statErr != nil || !info.Mode().IsRegular() {
		return "", "", "", httpapi.Fail(404, "Asset not found: "+asset)
	}
	if data, readErr := os.ReadFile(path + ".version"); readErr == nil {
		version = strings.TrimSpace(string(data))
	}
	return path, asset, version, nil
}
