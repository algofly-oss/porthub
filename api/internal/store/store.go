// Package store holds the MongoDB connection shared by all handlers.
package store

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func Connect(ctx context.Context, uri, database string) (*mongo.Database, func(), error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(15 * time.Second).
		SetBSONOptions(&options.BSONOptions{DefaultDocumentM: true})) // nested documents decode as bson.M, like Python dicts
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

// JSON converts Mongo values into what FastAPI's jsonable_encoder produces:
// ObjectId -> hex string, datetime -> naive ISO string, nested containers.
func JSON(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bson.ObjectID:
		return x.Hex()
	case bson.DateTime:
		return PyTime(x.Time())
	case time.Time:
		if x.IsZero() {
			return nil
		}
		return PyTime(x)
	case *time.Time:
		if x == nil {
			return nil
		}
		return PyTime(*x)
	case bson.M:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = JSON(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = JSON(val)
		}
		return out
	case bson.D:
		out := make(map[string]any, len(x))
		for _, e := range x {
			out[e.Key] = JSON(e.Value)
		}
		return out
	case bson.A:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = JSON(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = JSON(val)
		}
		return out
	case []bson.M:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = JSON(val)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = val
		}
		return out
	case int32:
		return int64(x)
	case bson.Decimal128:
		return x.String()
	}
	return v
}
