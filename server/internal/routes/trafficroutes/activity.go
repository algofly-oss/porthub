package trafficroutes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Incremental, privacy-minimal request counts from Traefik's JSON access log
// (api/shared/proxy_activity.py). The first run starts at EOF; totals and the
// read checkpoint share one Mongo document guarded by a revision.

const (
	stateID       = "traefik-requests-v1"
	maxBatchBytes = 2 * 1024 * 1024
)

func logPath() string {
	if p := os.Getenv("PROXY_ACCESS_LOG_PATH"); p != "" {
		return p
	}
	return "/runtime/traefik-access/access.log"
}

func fileIdentity(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino))
}

type checkpoint struct {
	identity string
	offset   int64
}

type record struct{ host, timestamp string }

type batch struct {
	identity string
	offset   int64
	records  []record
}

// readBatch mirrors read_batch; nil when the log does not exist.
func readBatch(path string, cp *checkpoint) (*batch, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	identity := fileIdentity(info)
	if cp == nil {
		return &batch{identity: identity, offset: info.Size()}, nil
	}
	if cp.identity != identity {
		if rotated, err := os.Stat(path + ".1"); err == nil {
			if fileIdentity(rotated) == cp.identity && rotated.Size() > cp.offset {
				return readBatch(path+".1", cp)
			}
		}
	}
	var offset int64
	if cp.identity == identity && cp.offset <= info.Size() {
		offset = cp.offset
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	chunk := make([]byte, maxBatchBytes)
	n, err := io.ReadFull(f, chunk)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	chunk = chunk[:n]
	end := bytes.LastIndexByte(chunk, '\n') + 1
	if end == 0 {
		// Leave an incomplete final line for the next read; a malformed
		// oversized line cannot pin the reader.
		if n == maxBatchBytes {
			offset += int64(n)
		}
		return &batch{identity: identity, offset: offset}, nil
	}
	return &batch{identity: identity, offset: offset + int64(end), records: parseRecords(chunk[:end])}, nil
}

// splitLines mirrors bytes.splitlines (\n, \r and \r\n).
func splitLines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' || b[i] == '\r' {
			lines = append(lines, b[start:i])
			if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

var fractionRE = regexp.MustCompile(`\.(\d+)`)

func parseRecords(chunk []byte) []record {
	records := []record{}
	for _, line := range splitLines(chunk) {
		var rec map[string]any
		if json.Unmarshal(line, &rec) != nil || rec == nil {
			continue
		}
		host := strings.ToLower(pyStr(rec, "RequestHost"))
		host, _, _ = strings.Cut(host, ":")
		host = strings.TrimRight(host, ".")
		stamp := strings.ReplaceAll(pyStr(rec, "StartUTC"), "Z", "+00:00")
		// Go emits RFC3339 nanoseconds; Python 3.10 only parsed 3 or 6 digits.
		stamp = fractionRE.ReplaceAllStringFunc(stamp, func(m string) string {
			digits := m[1:]
			if len(digits) > 6 {
				digits = digits[:6]
			}
			return "." + digits + strings.Repeat("0", 6-len(digits))
		})
		ts, ok := parseISO(stamp)
		if !ok || !truthy(rec["RouterName"]) {
			continue
		}
		records = append(records, record{host, isoUTC(ts)})
	}
	return records
}

func pyStr(rec map[string]any, key string) string {
	v, ok := rec[key]
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

var isoRE = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2}).(\d{2})(?::(\d{2})(?::(\d{2})(?:\.(\d{3}|\d{6}))?)?)?([+-])(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{6}))?)?$`)

// parseISO accepts what datetime.fromisoformat (Python 3.10) accepts with a
// UTC offset; values without an offset are rejected (they were skipped).
func parseISO(s string) (time.Time, bool) {
	m := isoRE.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	num := func(i int) int { n, _ := strconv.Atoi(m[i]); return n }
	year, month, day, hour, minute, second := num(1), num(2), num(3), num(4), num(5), num(6)
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	micro := 0
	if m[7] != "" {
		micro = num(7)
		if len(m[7]) == 3 {
			micro *= 1000
		}
	}
	offset := time.Duration(num(9))*time.Hour + time.Duration(num(10))*time.Minute + time.Duration(num(11))*time.Second
	if m[12] != "" {
		offset += time.Duration(num(12)) * time.Microsecond
	}
	if offset >= 24*time.Hour {
		return time.Time{}, false
	}
	if m[8] == "-" {
		offset = -offset
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, micro*1000, time.UTC).Add(-offset)
	return t, true
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// isoUTC mirrors datetime.isoformat() of an aware UTC datetime.
func isoUTC(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

func metricMap(v any) map[string]any {
	d, ok := core.AsMap(v)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(d))
	for k, val := range d {
		out[k] = val
	}
	return out
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func intOf(m map[string]any, key string) int {
	n, _ := core.AsInt(m[key])
	return n
}

func prefix(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// applyRecords mirrors apply_records: only registered hosts are counted;
// metrics of removed routes are dropped.
func applyRecords(metrics map[string]any, records []record, routes []core.Doc, trackingSince string) map[string]any {
	byHost := map[string]string{}
	valid := map[string]bool{}
	for _, route := range routes {
		id := core.IDString(route["_id"])
		valid[id] = true
		for _, host := range core.List(route, "hosts") {
			if s, ok := host.(string); ok {
				byHost[strings.ToLower(s)] = id
			}
		}
	}
	result := map[string]any{}
	for key, value := range metrics {
		if valid[key] {
			if m := metricMap(value); m != nil {
				result[key] = m
			}
		}
	}
	// Upgrade old lifetime-only counters when the whole history is one month.
	for _, value := range result {
		metric := value.(map[string]any)
		lastMonth := prefix(str(metric, "last_requested_at"), 7)
		if _, has := metric["month"]; !has && trackingSince != "" && lastMonth == prefix(trackingSince, 7) {
			metric["month"] = lastMonth
			metric["monthly_requests"] = core.Get(metric, "requests", 0)
		}
	}
	for _, rec := range records {
		id, ok := byHost[rec.host]
		if !ok {
			continue
		}
		metric, _ := result[id].(map[string]any)
		if metric == nil {
			metric = map[string]any{"requests": 0, "last_requested_at": nil}
			result[id] = metric
		}
		metric["requests"] = intOf(metric, "requests") + 1
		month := prefix(rec.timestamp, 7)
		if month > str(metric, "month") {
			metric["month"] = month
			metric["monthly_requests"] = 0
		}
		if month == str(metric, "month") {
			metric["monthly_requests"] = intOf(metric, "monthly_requests") + 1
		}
		if last := str(metric, "last_requested_at"); last == "" || rec.timestamp > last {
			metric["last_requested_at"] = rec.timestamp
			metric["last_host"] = rec.host
		}
	}
	return result
}

func previousSegmentAvailable(path, identity string, offset int64) bool {
	info, err := os.Stat(path + ".1")
	return err == nil && fileIdentity(info) == identity && offset <= info.Size()
}

func nowISO() string { return isoUTC(time.Now()) }

// collect mirrors collect_proxy_activity.
func collect(ctx context.Context, app *core.App, path string) error {
	state, err := app.FindOne(ctx, "proxy_activity", bson.M{"_id": stateID})
	if err != nil {
		return err
	}
	var cp *checkpoint
	if state != nil {
		offset, _ := core.AsInt(state["offset"])
		cp = &checkpoint{identity: core.Str(state, "identity"), offset: int64(offset)}
	}
	b, err := readBatch(path, cp)
	if err != nil || b == nil {
		return err
	}
	now := nowISO()
	if state == nil {
		_, err := app.C("proxy_activity").UpdateOne(ctx, bson.M{"_id": stateID}, bson.M{"$setOnInsert": bson.D{
			{Key: "identity", Value: b.identity}, {Key: "offset", Value: int(b.offset)}, {Key: "revision", Value: 0},
			{Key: "tracking_since", Value: now}, {Key: "updated_at", Value: now}, {Key: "metrics", Value: bson.M{}},
		}}, options.UpdateOne().SetUpsert(true))
		return err
	}
	if b.identity == cp.identity && b.offset == cp.offset {
		return nil
	}
	routes, err := app.FindAll(ctx, "traffic_routes", bson.M{}, options.Find().SetProjection(bson.M{"_id": 1, "hosts": 1}))
	if err != nil {
		return err
	}
	trackingSince := core.Str(state, "tracking_since")
	metrics := applyRecords(metricMap(state["metrics"]), b.records, routes, trackingSince)
	gap := b.identity == cp.identity && b.offset < cp.offset
	if b.identity != cp.identity {
		gap = !previousSegmentAvailable(path, cp.identity, cp.offset)
	}
	monthlySince := state["monthly_tracking_since"]
	if !core.Truthy(state, "monthly_tracking_since") {
		if prefix(pyString(core.Get(state, "tracking_since", "")), 7) == prefix(now, 7) {
			monthlySince = state["tracking_since"]
		} else {
			monthlySince = now
		}
	}
	_, err = app.C("proxy_activity").UpdateOne(ctx, bson.M{"_id": stateID, "revision": state["revision"]}, bson.M{
		"$set": bson.D{
			{Key: "identity", Value: b.identity}, {Key: "offset", Value: int(b.offset)}, {Key: "metrics", Value: metrics},
			{Key: "updated_at", Value: now}, {Key: "monthly_tracking_since", Value: monthlySince},
			{Key: "coverage_warning", Value: core.Truthy(state, "coverage_warning") || gap},
		},
		"$inc": bson.M{"revision": 1},
	})
	return err
}

// pyString mirrors str(value) for stored scalars.
func pyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	}
	return fmt.Sprint(core.JSON(v))
}

// RunProxyActivity mirrors monitor_proxy_activity: one batch every 5 seconds.
func RunProxyActivity(ctx context.Context, app *core.App) {
	path := logPath()
	for {
		if err := collect(ctx, app, path); err != nil && ctx.Err() == nil {
			log.Printf("Proxy request analytics could not read its next batch: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

type activityOut struct{ Body map[string]any }

// activity mirrors GET /traffic-routes/activity.
func (h *handlers) activity(ctx context.Context, _ *struct{}) (*activityOut, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := h.app.FindAll(ctx, "traffic_routes", bson.M{"user_id": user["_id"]}, options.Find().SetProjection(bson.M{"_id": 1, "hosts": 1}))
	if err != nil {
		return nil, err
	}
	state, err := h.app.FindOne(ctx, "proxy_activity", bson.M{"_id": stateID})
	if err != nil {
		return nil, err
	}
	return &activityOut{Body: activityBody(routes, state, time.Now().UTC().Format("2006-01"))}, nil
}

func activityBody(routes []core.Doc, state core.Doc, month string) map[string]any {
	available := state != nil
	if state == nil {
		state = core.Doc{}
	}
	metrics := metricMap(core.Get(state, "metrics", nil))
	trackingMonth := prefix(pyString(core.Get(state, "tracking_since", "")), 7)
	data := []any{}
	for _, route := range routes {
		id := core.IDString(route["_id"])
		metric := metricMap(metrics[id])
		if metric == nil {
			metric = map[string]any{"requests": 0, "last_requested_at": nil}
		}
		var monthly any = 0
		if v, ok := metric["month"]; ok && v == month {
			monthly = core.Get(metric, "monthly_requests", 0)
		}
		if _, has := metric["month"]; !has && trackingMonth == month {
			monthly = core.Get(metric, "requests", 0)
		}
		item := map[string]any{"route_id": id}
		for k, v := range metric {
			item[k] = core.JSON(v)
		}
		item["monthly_requests"] = core.JSON(monthly)
		data = append(data, item)
	}
	return map[string]any{
		"tracking_since":         core.JSON(state["tracking_since"]),
		"updated_at":             core.JSON(state["updated_at"]),
		"month":                  month,
		"monthly_tracking_since": core.JSON(state["monthly_tracking_since"]),
		"available":              available,
		"coverage_warning":       core.Truthy(state, "coverage_warning"),
		"data":                   data,
	}
}
