package connections

import (
	"context"
	"log"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Timings of api/shared/connection_refresh.py.
var (
	refreshPollInterval = 30 * time.Second
	refreshReenableWait = 5 * time.Second
	refreshRetryDelay   = 60 * time.Second
)

func nextRefreshAt(now time.Time, minutes any) time.Time {
	n, ok := core.AsInt(minutes)
	if !ok || n == 0 {
		n = 60
	}
	return now.Add(time.Duration(max(1, n)) * time.Minute)
}

// applyEnabled mirrors _apply_connection_enabled.
func applyEnabled(ctx context.Context, app *core.App, connection core.Doc, enabled bool) (core.Doc, error) {
	_, err := app.C("connections").UpdateOne(ctx, bson.M{"_id": connection["_id"]},
		bson.M{"$set": bson.D{{Key: "enabled", Value: enabled}, {Key: "updated_at", Value: core.Now()}}})
	if err != nil {
		return nil, err
	}
	updated, err := app.FindOne(ctx, "connections", bson.M{"_id": connection["_id"]})
	if err != nil || updated == nil {
		return nil, err
	}
	if err := app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	if core.Truthy(updated, "machine_id") && app.Events != nil {
		app.Events.MachineConfigChanged(ctx, core.IDString(updated["machine_id"]))
	}
	app.SyncConnectionFirewall(ctx, updated)
	return updated, nil
}

func retryAt(connection core.Doc) any {
	if core.Truthy(connection, "auto_refresh_enabled") {
		return core.Now().Add(refreshRetryDelay)
	}
	return nil
}

// RefreshConnection mirrors refresh_connection_config: disable the
// connection, wait, enable it again and schedule the next auto refresh. It
// returns nil when the connection could not be refreshed (errors after the
// machine lookup are logged, like Python). Cancelling ctx while waiting
// re-enables the connection before returning.
func RefreshConnection(ctx context.Context, app *core.App, connection core.Doc, force bool) (core.Doc, error) {
	connectionID := connection["_id"]
	interval := connection["auto_refresh_interval_minutes"]
	machine, err := app.FindOne(ctx, "machines", bson.M{"_id": connection["machine_id"], "enabled": bson.M{"$ne": false}})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		_, err := app.C("connections").UpdateOne(ctx, bson.M{"_id": connectionID},
			bson.M{"$set": bson.M{"auto_refresh_next_at": retryAt(connection)}})
		return nil, err
	}
	log.Printf("Auto-refreshing connection %s on machine %s", core.IDString(connectionID), core.IDString(machine["_id"]))

	var disabled core.Doc
	reenabled := false
	run := func() (core.Doc, error) {
		var err error
		if disabled, err = applyEnabled(ctx, app, connection, false); err != nil || disabled == nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(refreshReenableWait):
		}
		latest, err := app.FindOne(ctx, "connections", bson.M{"_id": connectionID})
		if err != nil || latest == nil {
			return nil, err
		}
		if !force && !core.Truthy(latest, "auto_refresh_enabled") {
			if _, err := applyEnabled(ctx, app, latest, true); err != nil {
				return nil, err
			}
			reenabled = true
			return nil, nil
		}
		refreshed, err := applyEnabled(ctx, app, latest, true)
		if err != nil || refreshed == nil {
			return nil, err
		}
		reenabled = true
		refreshedAt := core.Now()
		var next any
		if core.Truthy(refreshed, "auto_refresh_enabled") {
			next = nextRefreshAt(refreshedAt, interval)
		}
		if _, err := app.C("connections").UpdateOne(ctx, bson.M{"_id": connectionID},
			bson.M{"$set": bson.D{{Key: "auto_refreshed_at", Value: refreshedAt}, {Key: "auto_refresh_next_at", Value: next}}}); err != nil {
			return nil, err
		}
		return app.FindOne(ctx, "connections", bson.M{"_id": connectionID})
	}
	result, err := run()
	if err == nil {
		return result, nil
	}

	// Recover: never leave a connection disabled by an interrupted refresh.
	cleanup := context.WithoutCancel(ctx)
	cancelled := ctx.Err() != nil
	if !cancelled {
		log.Printf("Failed to auto-refresh connection %s: %v", core.IDString(connectionID), err)
	}
	latest, _ := app.FindOne(cleanup, "connections", bson.M{"_id": connectionID})
	if disabled != nil && !reenabled && latest != nil {
		if _, err := applyEnabled(cleanup, app, latest, true); err != nil {
			log.Printf("Failed to re-enable connection %s: %v", core.IDString(connectionID), err)
		}
	}
	if !cancelled {
		_, _ = app.C("connections").UpdateOne(cleanup, bson.M{"_id": connectionID},
			bson.M{"$set": bson.M{"auto_refresh_next_at": retryAt(connection)}})
	}
	return nil, nil
}

// RunAutoRefresh mirrors monitor_connection_auto_refresh (the Go API is a
// single process, so it always acts as the leader).
func RunAutoRefresh(ctx context.Context, app *core.App) {
	for ctx.Err() == nil {
		due, err := app.FindAll(ctx, "connections", bson.M{
			"enabled":                       bson.M{"$ne": false},
			"auto_refresh_enabled":          true,
			"auto_refresh_interval_minutes": bson.M{"$gte": 1},
			"$or": bson.A{
				bson.M{"auto_refresh_next_at": bson.M{"$lte": core.Now()}},
				bson.M{"auto_refresh_next_at": bson.M{"$exists": false}},
				bson.M{"auto_refresh_next_at": nil},
			},
		}, options.Find().SetLimit(25))
		if err != nil && ctx.Err() == nil {
			log.Printf("Connection auto refresh: %v", err)
		}
		for _, connection := range due {
			if ctx.Err() != nil {
				break
			}
			if _, err := RefreshConnection(ctx, app, connection, false); err != nil && ctx.Err() == nil {
				log.Printf("Connection auto refresh: %v", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(refreshPollInterval):
		}
	}
}
