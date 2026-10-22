package clientassets

import (
	"context"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runShell(t *testing.T, code string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required for the shell client checks")
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "assets", "client", "porthub-client.sh"))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndex(string(source), `main "$@"`)
	if end < 0 {
		t.Fatal("client entrypoint not found")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "client.sh")
	if err := os.WriteFile(script, source[:end], 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bash, "-c", "source \"$TEST_CLIENT\"\n"+code)
	command.Env = append(os.Environ(), "TEST_CLIENT="+script, "TEST_DIR="+dir)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("shell check: %v\n%s", err, out)
	}
	return string(out)
}

func TestStalledRequestsAreBoundedAndRetryable(t *testing.T) {
	runShell(t, `
state_get() { printf initial; }
debug_log() { :; }
build_sync_payload() { printf '{}'; }
curl() { printf '%s\n' "$@" > "$TEST_DIR/curl-args"; printf 000; return 28; }
PORT_HUB_CHANGES_TOML_URL=http://localhost/changes
PORT_HUB_CHANGES_WAIT_SECONDS=25
if poll_for_change; then exit 1; fi
awk 'p=="--connect-timeout" && $0==10 {c=1} p=="--max-time" && $0==40 {m=1} {p=$0} END {exit !(c&&m)}' "$TEST_DIR/curl-args"
if machine_post http://localhost/sync true; then exit 1; fi
awk 'p=="--connect-timeout" && $0==10 {c=1} p=="--max-time" && $0==60 {m=1} {p=$0} END {exit !(c&&m)}' "$TEST_DIR/curl-args"
`)
}

func TestPrivateAddressCacheAndRevocation(t *testing.T) {
	runShell(t, `
PORT_HUB_STATE_FILE="$TEST_DIR/state"
SUDO=""
PORT_HUB_PRIVATE_IPS="10.203.0.87, 10.204.0.2"
write_state
[ "$(state_get PORT_HUB_PRIVATE_IPS)" = "10.203.0.87, 10.204.0.2" ]
unset PORT_HUB_PRIVATE_IPS
write_state
[ "$(state_get PORT_HUB_PRIVATE_IPS)" = "10.203.0.87, 10.204.0.2" ]
PORT_HUB_PRIVATE_IPS=""
write_state
[ -z "$(state_get PORT_HUB_PRIVATE_IPS)" ]
`)
}

func TestMacUpdateKeepsLoadedJobRegistered(t *testing.T) {
	runShell(t, `
service_manager() { printf launchd; }
launchctl() { printf '%s\n' "$1" >> "$TEST_DIR/launch-commands"; }
save_state() { :; }
SUDO=""
PORT_HUB_SERVICE_LABEL=com.porthub.client.test
PORT_HUB_SERVICE_FILE="$TEST_DIR/service.plist"
service_enable_and_start
! grep -qx bootout "$TEST_DIR/launch-commands"
! grep -qx bootstrap "$TEST_DIR/launch-commands"
grep -qx kickstart "$TEST_DIR/launch-commands"
`)
}

func TestEmptyDaemonArguments(t *testing.T) {
	if got := runShell(t, "service_run_cmd() { printf parsed; }\nmain __service-run --tenant test\n"); got != "parsed" {
		t.Fatalf("got %q", got)
	}
}

func TestLaunchdCrashIsNotRunning(t *testing.T) {
	for _, tc := range []struct{ state, want string }{{"spawn scheduled", "stopped"}, {"running", "running"}} {
		t.Run(tc.state, func(t *testing.T) {
			got := runShell(t, "service_manager() { printf launchd; }\nlaunchctl() { printf 'state = "+tc.state+"\\n'; }\nservice_status\n")
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReleaseMigratesOnlyItsOwnTenant(t *testing.T) {
	runShell(t, `
PORT_HUB_MACHINE_ID=own
PORT_HUB_DEFAULT_MACHINE_ID=other
PORT_HUB_API_URL=http://old/api
PORT_HUB_DEFAULT_API_URL=https://new/api
refresh_derived_urls() { :; }
write_env_file() { printf migrated > "$TEST_DIR/migrated"; }
migrate_release_server
[ ! -f "$TEST_DIR/migrated" ]
[ "$PORT_HUB_API_URL" = http://old/api ]
PORT_HUB_DEFAULT_MACHINE_ID=own
migrate_release_server
[ -f "$TEST_DIR/migrated" ]
[ "$PORT_HUB_API_URL" = https://new/api ]
`)
}

func TestMacDaemonStartsAtBootAndRecovers(t *testing.T) {
	plist := runShell(t, `
service_manager() { printf launchd; }
PORT_HUB_SERVICE_FILE="$TEST_DIR/service.plist"
PORT_HUB_SELF_PATH=/usr/local/bin/porthub
PORT_HUB_TENANT=test
PORT_HUB_SERVICE_LABEL=com.porthub.client.test
PORT_HUB_DIR=/usr/local/etc/porthub/tenants/test
PORT_HUB_LOG_DIR=/usr/local/var/log/porthub/test
SUDO=""
write_service_file
cat "$PORT_HUB_SERVICE_FILE"
`)
	decoder := xml.NewDecoder(strings.NewReader(plist))
	entries := map[string]string{}
	arrays := map[string][]string{}
	var key string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			if err := decoder.DecodeElement(&key, &start); err != nil {
				t.Fatal(err)
			}
		case "true":
			entries[key] = "true"
		case "string", "integer":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			entries[key] = value
		case "array":
			var value struct {
				Strings []string `xml:"string"`
			}
			if err := decoder.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			arrays[key] = value.Strings
		}
	}
	for name, want := range map[string]string{"RunAtLoad": "true", "KeepAlive": "true", "ThrottleInterval": "5"} {
		if entries[name] != want {
			t.Errorf("%s: got %q, want %q", name, entries[name], want)
		}
	}
	if got := strings.Join(arrays["ProgramArguments"], " "); got != "/usr/local/bin/porthub __service-run --tenant test" {
		t.Errorf("daemon arguments: %s", got)
	}
	if entries["StandardErrorPath"] == "" {
		t.Error("missing daemon error log")
	}
}
