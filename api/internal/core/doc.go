// Package core holds the logic shared by every API area (the Python
// api/shared package and api/router/common.py): Mongo document helpers,
// serializers, generated Rathole/Traefik configuration, the firewall client
// and the machine client configuration bundle.
package core

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/api/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Doc is a Mongo document read as a map, like a Python dict from motor.
type Doc = bson.M

// Str mirrors (doc.get(key) or "") for string fields; non-strings give "".
func Str(d Doc, key string) string {
	s, _ := d[key].(string)
	return s
}

// Trim mirrors (doc.get(key) or "").strip().
func Trim(d Doc, key string) string { return strings.TrimSpace(Str(d, key)) }

// IsFalse mirrors doc.get(key, True) is False.
func IsFalse(d Doc, key string) bool {
	v, ok := d[key].(bool)
	return ok && !v
}

// Truthy mirrors bool(doc.get(key)).
func Truthy(d Doc, key string) bool { return truthy(d[key]) }

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int32:
		return x != 0
	case int64:
		return x != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case bson.A:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case bson.M:
		return len(x) > 0
	case bson.D:
		return len(x) > 0
	}
	return true
}

// Int returns an integer field (Python isinstance(v, int), bools excluded).
func Int(d Doc, key string) (int, bool) { return AsInt(d[key]) }

func AsInt(v any) (int, bool) {
	switch x := v.(type) {
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case int:
		return x, true
	}
	return 0, false
}

// Number returns an int or float field as float64.
func Number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x)
	case float32:
		return float64(x), true
	}
	i, ok := AsInt(v)
	return float64(i), ok
}

// Time returns a datetime field.
func Time(d Doc, key string) (time.Time, bool) { return AsTime(d[key]) }

func AsTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case bson.DateTime:
		return x.Time().UTC(), true
	case time.Time:
		return x.UTC(), true
	}
	return time.Time{}, false
}

// OID returns an ObjectId field (or a valid hex string, like ObjectId(str)).
func OID(d Doc, key string) (bson.ObjectID, bool) { return AsOID(d[key]) }

func AsOID(v any) (bson.ObjectID, bool) {
	switch x := v.(type) {
	case bson.ObjectID:
		return x, true
	case string:
		id, err := bson.ObjectIDFromHex(x)
		return id, err == nil
	}
	return bson.ObjectID{}, false
}

// IDString mirrors str(value) for ids: ObjectId hex, strings as-is.
func IDString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bson.ObjectID:
		return x.Hex()
	case string:
		return x
	}
	return fmt.Sprint(v)
}

// List returns an array field as []any (nil when missing or not a list).
func List(d Doc, key string) []any { return AsList(d[key]) }

func AsList(v any) []any {
	switch x := v.(type) {
	case bson.A:
		return x
	case []any:
		return x
	}
	return nil
}

// Map returns an embedded document field.
func Map(d Doc, key string) (Doc, bool) { return AsMap(d[key]) }

func AsMap(v any) (Doc, bool) {
	switch x := v.(type) {
	case bson.M:
		return x, true
	case map[string]any:
		return x, true
	case bson.D:
		m := bson.M{}
		for _, e := range x {
			m[e.Key] = e.Value
		}
		return m, true
	}
	return nil, false
}

// Get mirrors doc.get(key, fallback).
func Get(d Doc, key string, fallback any) any {
	if v, ok := d[key]; ok {
		return v
	}
	return fallback
}

// Now is datetime.utcnow() at Mongo's millisecond precision.
func Now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// JSON converts Mongo values into what FastAPI's jsonable_encoder produces:
// ObjectId -> hex string, datetime -> naive ISO string, nested containers.
func JSON(v any) any { return store.JSON(v) }
