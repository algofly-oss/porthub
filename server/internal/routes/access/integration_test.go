package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/server/internal/auth"
	"github.com/algofly-oss/porthub/server/internal/config"
	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Run with PORTHUB_TEST_MONGO_URI pointing at a disposable MongoDB server.
// Each run uses its own database and removes only that database.
func TestWorkspaceAndPrivateLifecycle(t *testing.T) {
	uri := os.Getenv("PORTHUB_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set PORTHUB_TEST_MONGO_URI for Mongo integration")
	}
	ctx := context.Background()
	db, closeDB, err := store.Connect(ctx, uri, "porthub_test_"+bson.NewObjectID().Hex())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	defer db.Drop(ctx)
	app := &core.App{DB: db, Cfg: config.Config{MachineOnlineTTL: time.Minute}, Sessions: &auth.Sessions{DB: db, Cookie: "session"}}
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	Register(s.API, app)
	owner, member, mid := bson.NewObjectID(), bson.NewObjectID(), bson.NewObjectID()
	insert := func(coll string, d bson.M) {
		t.Helper()
		if _, err := db.Collection(coll).InsertOne(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	insert("users", bson.M{"_id": owner, "name": "Owner", "username": "owner@example.org"})
	insert("users", bson.M{"_id": member, "name": "Member", "username": "member@example.org"})
	insert("user_sessions", bson.M{"_id": "owner-session", "user_id": owner.Hex()})
	insert("user_sessions", bson.M{"_id": "member-session", "user_id": member.Hex()})
	insert("machines", bson.M{"_id": mid, "user_id": owner, "name": "Server", "token": "must-not-leak", "enabled": true, "last_seen_at": core.Now()})
	call := func(method, path, body, session string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if session != "" {
			r.Header.Set("Cookie", "session="+session)
		}
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: %d %s, want %d", method, path, w.Code, w.Body.String(), status)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(w.Body.String(), "must-not-leak") {
			t.Fatal("machine token leaked")
		}
		return out
	}
	own := "owner-session"
	mem := "member-session"
	base := "/api/access"
	ws := call("GET", base+"/workspaces", "", own, 200)
	if len(ws["data"].([]any)) != 1 {
		t.Fatal(ws)
	}
	g := call("POST", base+"/groups", `{"name":"Production"}`, own, 200)["data"].(map[string]any)["_id"].(string)
	book := fmt.Sprintf(`{"name":"Fleet","group_id":%q,"rules":[]}`, g)
	b := call("POST", base+"/books", book, own, 200)["data"].(map[string]any)
	bid := b["_id"].(string)
	call("PUT", base+"/books/"+bid, strings.TrimSuffix(book, "}")+`,"revision":1}`, own, 200)
	call("PUT", base+"/books/"+bid, strings.TrimSuffix(book, "}")+`,"revision":1}`, own, 409)
	call("DELETE", base+"/books/"+bid, `{"revision":2}`, own, 200)
	invitation := call("POST", base+"/invitations", `{"email":"member@example.org"}`, own, 200)["token"].(string)
	payload := fmt.Sprintf(`{"token":%q}`, invitation)
	call("POST", base+"/invitations/preview", payload, "", 200)
	call("POST", base+"/invitations/accept", payload, mem, 200)
	call("POST", base+"/invitations/accept", payload, mem, 400)
	call("PUT", base+"/network?workspace="+owner.Hex(), `{}`, mem, 403)
	call("PUT", base+"/groups/"+g+"/members", fmt.Sprintf(`{"machine_ids":[%q],"user_ids":[%q]}`, mid.Hex(), member.Hex()), own, 200)
	enrolled := call("POST", base+"/private/peers", fmt.Sprintf(`{"machine_id":%q}`, mid.Hex()), own, 200)
	if enrolled["hostname"] != "server.phub" {
		t.Fatalf("enrollment hostname: %#v", enrolled["hostname"])
	}
	peer := enrolled["peer_id"].(string)
	ticket := fmt.Sprintf(`{"ticket":%q}`, enrolled["ticket"])
	creds := call("POST", base+"/private/bootstrap", ticket, "", 200)
	call("POST", base+"/private/bootstrap", ticket, "", 403)
	call("POST", base+"/private/peers", fmt.Sprintf(`{"machine_id":%q}`, mid.Hex()), own, 409)
	sync := fmt.Sprintf(`{"peer_id":%q,"token":%q,"fingerprint":%q,"instance":"abcdefghijklmnop"}`, peer, creds["token"], strings.Repeat("AA:", 31)+"AA")
	snapshot := call("POST", base+"/private/sync", sync, "", 200)["snapshot"].(map[string]any)
	if snapshot["peers"].([]any)[0].(map[string]any)["hostname"] != "server.phub" {
		t.Fatal("private sync lost its hostname")
	}
	if snapshot["self"] != peer || len(snapshot["peers"].([]any)) != 1 {
		t.Fatal(snapshot)
	}
	renamed := call("PUT", base+"/private/peers/"+peer+"/hostname", `{"hostname":"custom"}`, own, 200)
	if renamed["hostname"] != "custom" {
		t.Fatal("private rename lost its hostname")
	}
	call("GET", base+"/snapshot", "", own, 200)
	call("DELETE", base+"/private/peers/"+peer, "", own, 200)
	call("POST", base+"/private/sync", sync, "", 403)
	call("DELETE", base+"/members/"+member.Hex(), "", own, 200)
	call("GET", base+"/snapshot?workspace="+owner.Hex(), "", mem, 403)
}
