package machines

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/api/internal/auth"
	"github.com/algofly-oss/porthub/api/internal/config"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestShortInstallerTicket(t *testing.T) {
	uri := os.Getenv("PORTHUB_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set PORTHUB_TEST_MONGO_URI for Mongo integration")
	}
	ctx := context.Background()
	db, closeDB, err := store.Connect(ctx, uri, "porthub_install_test_"+bson.NewObjectID().Hex())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	defer db.Drop(ctx)
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "install.sh"), []byte("token=__PORT_HUB_MACHINE_TOKEN__\n"), 0600); err != nil {
		t.Fatal(err)
	}
	app := &core.App{DB: db, Cfg: config.Config{PublicBaseURL: "https://hub.example", ClientAssetsDir: dir, MachineOnlineTTL: time.Minute}, Sessions: &auth.Sessions{DB: db, Cookie: "session"}}
	owner, mid := bson.NewObjectID(), bson.NewObjectID()
	machineToken := strings.Repeat("secret", 8)
	for _, item := range []struct {
		coll string
		doc  bson.M
	}{{"users", bson.M{"_id": owner}}, {"user_sessions", bson.M{"_id": "test-session", "user_id": owner.Hex()}}, {"machines", bson.M{"_id": mid, "user_id": owner, "name": "test", "token": machineToken, "enabled": true}}} {
		if _, err = db.Collection(item.coll).InsertOne(ctx, item.doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	Register(s.API, app)
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Cookie", "session=test-session")
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, r)
		return w
	}
	w := request("/api/machines/command/" + mid.Hex())
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			Command string `json:"command"`
		} `json:"data"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	command := out.Data.Command
	if strings.Contains(command, machineToken) || strings.Contains(command, "/api/") {
		t.Fatal("installer command exposes internal token or API prefix")
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(command, "curl -fsSL "), " | bash")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	code := strings.TrimPrefix(u.Path, "/install/")
	if !regexp.MustCompile(`^[A-Za-z0-9]{16}$`).MatchString(code) {
		t.Fatalf("code length %d", len(code))
	}
	// Opening or closing Advanced options changes no effective setup values.
	again := request("/api/machines/command/" + mid.Hex() + "?public_base_url=https%3A%2F%2Fhub.example&service_domain=")
	var repeated struct {
		Data struct {
			Command string `json:"command"`
		} `json:"data"`
	}
	if err = json.Unmarshal(again.Body.Bytes(), &repeated); err != nil {
		t.Fatal(err)
	}
	if repeated.Data.Command != command {
		t.Fatal("identical setup generated a different installer code")
	}
	changed := request("/api/machines/command/" + mid.Hex() + "?public_base_url=https%3A%2F%2Fnew-hub.example")
	var changedURL struct {
		Data struct {
			Command string `json:"command"`
		} `json:"data"`
	}
	if err = json.Unmarshal(changed.Body.Bytes(), &changedURL); err != nil {
		t.Fatal(err)
	}
	if changedURL.Data.Command != "curl -fsSL https://new-hub.example/install/"+code+" | bash" {
		t.Fatal("changing the access URL changed the machine installer code")
	}
	// Updating a registered client automatically creates its private enrollment.
	if err = os.WriteFile(filepath.Join(dir, "private-install.sh"), []byte("server=__PRIVATE_SERVER__\nticket=__PRIVATE_TICKET__\n"), 0600); err != nil {
		t.Fatal(err)
	}
	privateRequest := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/machines/client/private-install", strings.NewReader(`{"machine_id":"`+mid.Hex()+`","token":"`+machineToken+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, r)
		return w
	}
	if w := privateRequest(); w.Code != 200 {
		t.Fatalf("automatic private enrollment: %d %s", w.Code, w.Body.String())
	}
	peerID := owner.Hex() + ":" + mid.Hex()
	peer, err := app.FindOne(ctx, "private_peers", bson.M{"_id": peerID})
	if err != nil || peer == nil || core.Str(peer, "ip") == "" {
		t.Fatalf("default peer missing: %v", err)
	}
	allocated := core.Str(peer, "ip")
	if err := EnsureDefaultPrivateNetworks(ctx, app); err != nil {
		t.Fatal(err)
	}
	repeatedPeer, _ := app.FindOne(ctx, "private_peers", bson.M{"_id": peerID})
	if core.Str(repeatedPeer, "ip") != allocated {
		t.Fatal("migration changed existing private IP")
	}
	if _, err = db.Collection("private_peers").UpdateOne(ctx, bson.M{"_id": peerID}, bson.M{"$set": bson.M{"ip": "10.203.0.87"}}); err != nil {
		t.Fatal(err)
	}
	addresses := request("/api/machines/private-addresses/" + mid.Hex())
	if addresses.Code != 200 || !strings.Contains(addresses.Body.String(), "10.203.0.87") {
		t.Fatalf("private addresses: %d %s", addresses.Code, addresses.Body.String())
	}
	listed := request("/api/machines/list")
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"private_ips":["10.203.0.87"]`) {
		t.Fatalf("machine list missing private IP: %d %s", listed.Code, listed.Body.String())
	}
	foreign := request("/api/machines/private-addresses/" + bson.NewObjectID().Hex())
	if foreign.Code != 404 {
		t.Fatalf("foreign machine exposed: %d", foreign.Code)
	}
	if w := privateRequest(); w.Code != 200 || strings.Contains(w.Body.String(), "__PRIVATE_") || !strings.Contains(w.Body.String(), "https://hub.example") {
		t.Fatalf("pending enrollment: %d %s", w.Code, w.Body.String())
	}
	if _, err = db.Collection("private_peers").UpdateOne(ctx, bson.M{"_id": peerID}, bson.M{"$set": bson.M{"workspace_id": bson.NewObjectID()}}); err != nil {
		t.Fatal(err)
	}
	if w := privateRequest(); w.Code != 403 {
		t.Fatalf("accepted enrollment without workspace membership: %d", w.Code)
	}
	if _, err = db.Collection("private_peers").UpdateOne(ctx, bson.M{"_id": peerID}, bson.M{"$set": bson.M{"credential_hash": "installed"}}); err != nil {
		t.Fatal(err)
	}
	if w := privateRequest(); w.Code != 204 {
		t.Fatalf("re-enrolled installed peer: %d", w.Code)
	}
	w = request(u.Path)
	if w.Code != 200 || !strings.Contains(w.Body.String(), machineToken) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if _, err = db.Collection("machine_install_tickets").UpdateOne(ctx, bson.M{"ticket_hash": core.TokenDigest(code)}, bson.M{"$set": bson.M{"expires_at": core.Now().Add(-time.Second)}}); err != nil {
		t.Fatal(err)
	}
	if w = request(u.Path); w.Code != 403 {
		t.Fatal("accepted expired installer ticket")
	}
	if _, err = db.Collection("machine_install_tickets").UpdateOne(ctx, bson.M{"ticket_hash": core.TokenDigest(code)}, bson.M{"$set": bson.M{"expires_at": core.Now().Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Collection("machines").UpdateOne(ctx, bson.M{"_id": mid}, bson.M{"$set": bson.M{"token": "rotated"}}); err != nil {
		t.Fatal(err)
	}
	if w = request(u.Path); w.Code != 403 {
		t.Fatal("ticket survived machine token revocation")
	}
}
