package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/algofly-oss/porthub/api/internal/config"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// runClients is local operator tooling; credentials never leave the process.
func runClients(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("clients", flag.ContinueOnError)
	request := flags.Bool("request-updates", false, "queue the bundled client release for registered machines")
	onlineOnly := flags.Bool("online-only", false, "only queue machines currently online")
	connections := flags.Bool("connections", false, "include public forwarding ports in the inventory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, closeDB, err := store.Connect(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		return err
	}
	defer closeDB()
	app := &core.App{DB: db, Cfg: cfg}
	rows, err := app.FindAll(ctx, "machines", bson.M{"enabled": bson.M{"$ne": false}, "deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return err
	}
	output := []map[string]any{}
	for _, m := range rows {
		online := app.IsOnline(m)
		queued := false
		if *request && (!*onlineOnly || online) {
			var id [8]byte
			if _, err := rand.Read(id[:]); err != nil {
				return err
			}
			_, err = app.C("machines").UpdateOne(ctx, bson.M{"_id": m["_id"]}, bson.M{"$set": bson.M{"client_update_target_version": app.ClientVersion(), "client_update_request_id": hex.EncodeToString(id[:]), "client_update_requested_at": core.Now()}})
			if err != nil {
				return err
			}
			queued = true
		}
		row := map[string]any{"id": core.IDString(m["_id"]), "name": core.Str(m, "name"), "online": online, "client_version": core.Str(m, "client_version"), "latest_version": app.ClientVersion(), "update_queued": queued}
		row["update_pending"] = queued || core.Str(m, "client_update_request_id") != core.Str(m, "client_update_last_handled_request_id")
		if *connections {
			cs, err := app.FindAll(ctx, "connections", bson.M{"machine_id": m["_id"], "enabled": bson.M{"$ne": false}})
			if err != nil {
				return err
			}
			ports := []map[string]any{}
			for _, c := range cs {
				ports = append(ports, map[string]any{"external_port": core.JSON(c["external_port"]), "internal_port": core.JSON(c["internal_port"]), "service": core.Str(c, "service_name")})
			}
			row["connections"] = ports
		}
		output = append(output, row)
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(data))
	return err
}
