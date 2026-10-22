package main

import (
	"context"
	"github.com/algofly-oss/porthub/api/internal/auth"
	"github.com/algofly-oss/porthub/api/internal/config"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/store"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/api/internal/core"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestAuditFingerprintsIgnoreRuntimeAndCredentials(t *testing.T) {
	first := []core.Doc{{"_id": bson.NewObjectID(), "name": "first", "token": "secret", "last_seen_at": time.Now()}, {"_id": bson.NewObjectID(), "name": "second"}}
	before := fingerprint(first, auditFields["machines"])
	first[0]["token"] = "rotated"
	first[0]["last_seen_at"] = time.Now().Add(time.Hour)
	first[0], first[1] = first[1], first[0]
	after := fingerprint(first, auditFields["machines"])
	if before != after {
		t.Fatal("volatile runtime data changed configuration fingerprint")
	}
	first[0]["name"] = "changed"
	if fingerprint(first, auditFields["machines"]) == before {
		t.Fatal("configuration change missed")
	}
	report := auditReport{Collections: map[string]auditCollection{"machines": before}}
	changed := auditReport{Collections: map[string]auditCollection{"machines": after}}
	if len(compareAudit(changed, report)) != 0 {
		t.Fatal("matching configuration failed comparison")
	}
	changed.Collections["machines"] = fingerprint(first, auditFields["machines"])
	if len(compareAudit(changed, report)) != 1 {
		t.Fatal("baseline change missed")
	}
}

func TestAuditSessionsStayOnLoopback(t *testing.T) {
	for _, raw := range []string{"https://example.com", "http://127.0.0.1.evil.example", "http://user:password@localhost", "http://localhost/?next=x", "file:///tmp/audit", "http://localhost/api", "http://localhost/#x"} {
		if _, err := auditBase(raw); err == nil {
			t.Errorf("accepted unsafe endpoint %s", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:47080/", "http://localhost:47080", "http://[::1]:47080"} {
		endpoint, err := auditBase(raw)
		if err != nil || strings.HasSuffix(endpoint, "/") {
			t.Errorf("loopback %s: %v", raw, err)
		}
	}
}

func TestAuditSocketAuthenticatedSnapshot(t *testing.T) {
	uri := os.Getenv("PORTHUB_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set PORTHUB_TEST_MONGO_URI for Mongo integration")
	}
	ctx := context.Background()
	db, closeDB, err := store.Connect(ctx, uri, "porthub_audit_test_"+bson.NewObjectID().Hex())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	defer db.Drop(ctx)
	owner := bson.NewObjectID()
	_, err = db.Collection("user_sessions").InsertOne(ctx, bson.M{"_id": "test-session", "user_id": owner.Hex(), "expires_at": time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	app := &core.App{DB: db, Cfg: config.Config{SessionCookie: "session"}, Sessions: &auth.Sessions{DB: db, Cookie: "session"}}
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	registerAPI(s, app)
	server := httptest.NewServer(s.Mux)
	defer server.Close()
	if err := auditSocket(ctx, server.URL, "session", "test-session"); err != nil {
		t.Fatal(err)
	}
	invalidCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := auditSocket(invalidCtx, server.URL, "session", "invalid"); err == nil {
		t.Fatal("unauthenticated Socket.IO snapshot returned")
	}
}
