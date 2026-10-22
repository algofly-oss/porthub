// Package store holds the MongoDB connection shared by all handlers.
package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func Connect(ctx context.Context, uri, database string) (*mongo.Database, func(), error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(15 * time.Second))
	if err != nil {
		return nil, nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err = client.Ping(pingCtx, nil); err != nil {
		return nil, nil, fmt.Errorf("mongodb: %w", err)
	}
	return client.Database(database), func() { _ = client.Disconnect(context.Background()) }, nil
}

// PyTime formats a stored UTC time exactly like FastAPI's encoder does for a
// naive datetime: no zone, microseconds only when non-zero.
func PyTime(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}
