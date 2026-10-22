package realtime

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	ctsStatusSnapshot   = "/cts/machines/status-snapshot"
	stcStatusSnapshot   = "/stc/machines/status-snapshot"
	stcStatusChanged    = "/stc/machines/status-changed"
	ctsConfigSnapshot   = "/cts/machines/config-snapshot"
	stcConfigSnapshot   = "/stc/machines/config-snapshot"
	stcConfigChanged    = "/stc/machines/config-changed"
	ctsLogSubscribe     = "/cts/machines/log-stream-subscribe"
	ctsLogUnsubscribe   = "/cts/machines/log-stream-unsubscribe"
	stcLogStreamStatus  = "/stc/machines/log-stream-status"
	stcLogStreamLine    = "/stc/machines/log-stream-line"
	machineRoomPrefix   = "machine:"
	machineLogRoomPrefx = "machine-log:"
)

// Hub implements core.Events.
type Hub struct {
	app *core.App
	srv *server

	mu          sync.Mutex
	status      map[string]bool
	machineSIDs map[string]map[string]bool
	logSubs     map[string]map[string]bool // machine id -> sids
	logBySID    map[string]map[string]bool // sid -> machine ids
}

func New(app *core.App) *Hub {
	h := &Hub{app: app, srv: newServer(), status: map[string]bool{}, machineSIDs: map[string]map[string]bool{},
		logSubs: map[string]map[string]bool{}, logBySID: map[string]map[string]bool{}}
	h.srv.onConnect = h.connect
	h.srv.onEvent = h.event
	h.srv.onDisconnect = h.disconnect
	app.Events = h
	return h
}

// Handler serves /socket.io/.
func (h *Hub) Handler() http.Handler { return h.srv }

func addTo(m map[string]map[string]bool, key, value string) {
	if m[key] == nil {
		m[key] = map[string]bool{}
	}
	m[key][value] = true
}

func removeFrom(m map[string]map[string]bool, key, value string) {
	if set := m[key]; set != nil {
		delete(set, value)
		if len(set) == 0 {
			delete(m, key)
		}
	}
}

func (h *Hub) connect(ctx context.Context, c *conn, r *http.Request, auth map[string]any) bool {
	userID := ""
	if cookie, err := r.Cookie(h.app.Cfg.SessionCookie); err == nil {
		userID = h.app.Sessions.UserID(ctx, cookie.Value)
	}
	if userID != "" {
		c.mu.Lock()
		c.session["user_id"] = userID
		c.mu.Unlock()
		h.srv.join(c, userID)
		return true
	}
	if role, _ := auth["role"].(string); role == "machine" {
		id, _ := auth["machine_id"].(string)
		token, _ := auth["token"].(string)
		machine, err := h.app.AuthenticateMachine(ctx, id, token)
		if err != nil {
			return false
		}
		machineID := core.IDString(machine["_id"])
		c.mu.Lock()
		c.session["role"], c.session["machine_id"], c.session["user_id"] = "machine", machineID, core.IDString(machine["user_id"])
		c.mu.Unlock()
		h.srv.join(c, machineRoomPrefix+machineID)
		h.mu.Lock()
		addTo(h.machineSIDs, machineID, c.sid)
		h.mu.Unlock()
	}
	return true
}

func (h *Hub) disconnect(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if id := c.get("machine_id"); id != "" {
		removeFrom(h.machineSIDs, id, c.sid)
	}
	for machineID := range h.logBySID[c.sid] {
		removeFrom(h.logSubs, machineID, c.sid)
	}
	delete(h.logBySID, c.sid)
}

func (h *Hub) event(ctx context.Context, c *conn, event string, data any) {
	switch event {
	case ctsStatusSnapshot:
		if userID := c.get("user_id"); userID != "" {
			h.statusSnapshot(ctx, userID, c.sid)
		}
	case ctsConfigSnapshot:
		if c.get("role") != "machine" {
			return
		}
		id, ok := core.AsOID(c.get("machine_id"))
		if !ok {
			return
		}
		machine, _ := h.app.FindOne(ctx, "machines", bson.M{"_id": id})
		if machine == nil {
			return
		}
		h.emitConfig(ctx, stcConfigSnapshot, machine, c.sid)
	case ctsLogSubscribe, ctsLogUnsubscribe:
		userID := c.get("user_id")
		m, _ := core.AsMap(data)
		machineID, _ := m["machine_id"].(string)
		if userID == "" || machineID == "" || !core.ValidOID(machineID) {
			return
		}
		mid, _ := core.AsOID(machineID)
		uid, ok := core.AsOID(userID)
		if !ok {
			return
		}
		machine, _ := h.app.FindOne(ctx, "machines", bson.M{"_id": mid, "user_id": uid})
		if machine == nil {
			return
		}
		subscribe := event == ctsLogSubscribe
		h.mu.Lock()
		if subscribe {
			addTo(h.logSubs, machineID, c.sid)
			addTo(h.logBySID, c.sid, machineID)
		} else {
			removeFrom(h.logSubs, machineID, c.sid)
			removeFrom(h.logBySID, c.sid, machineID)
		}
		h.mu.Unlock()
		if subscribe {
			h.srv.join(c, machineLogRoomPrefx+machineID)
		} else {
			h.srv.leave(c, machineLogRoomPrefx+machineID)
		}
		h.logStreamStatus(machine, c.sid, &subscribe)
	}
}

// --- core.Events ---

func (h *Hub) Emit(event string, data any, room string) { h.srv.emit(event, core.JSON(data), room) }

func (h *Hub) statusSnapshot(ctx context.Context, userID, room string) {
	uid, ok := core.AsOID(userID)
	if !ok {
		return
	}
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"user_id": uid, "deletion_pending": bson.M{"$ne": true}},
		options.Find().SetSort(core.Sort("created_at", 1)))
	if err != nil {
		return
	}
	out := []any{}
	for _, m := range machines {
		out = append(out, h.app.SerializeMachine(m))
	}
	h.srv.emit(stcStatusSnapshot, map[string]any{"machines": out}, room)
}

func (h *Hub) LogStreamRequested(machineID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.logSubs[machineID]) > 0
}

func (h *Hub) logStreamStatus(machine core.Doc, room string, subscribed *bool) {
	machineID := core.IDString(machine["_id"])
	payload := map[string]any{"machine_id": machineID, "machine_online": h.app.IsOnline(machine), "stream_requested": h.LogStreamRequested(machineID)}
	if subscribed != nil {
		payload["subscribed"] = *subscribed
	}
	if room == "" {
		room = core.IDString(machine["user_id"])
	}
	h.srv.emit(stcLogStreamStatus, payload, room)
}

func (h *Hub) MachineStatusChanged(ctx context.Context, machine core.Doc) {
	h.srv.emit(stcStatusChanged, map[string]any{"machine": h.app.SerializeMachine(machine)}, core.IDString(machine["user_id"]))
	h.logStreamStatus(machine, machineLogRoomPrefx+core.IDString(machine["_id"]), nil)
}

func (h *Hub) emitConfig(ctx context.Context, event string, machine core.Doc, room string) {
	bundle, err := h.app.MachineConfigBundle(ctx, machine, nil)
	if err != nil {
		log.Printf("machine config bundle: %v", err)
		return
	}
	id := core.IDString(machine["_id"])
	if room == "" {
		room = machineRoomPrefix + id
	}
	h.srv.emit(event, map[string]any{"machine_id": id, "config": bundle}, room)
}

func (h *Hub) MachineConfigChanged(ctx context.Context, machineID string) {
	id, ok := core.AsOID(machineID)
	if !ok {
		return
	}
	machine, _ := h.app.FindOne(ctx, "machines", bson.M{"_id": id})
	if machine != nil {
		h.emitConfig(ctx, stcConfigChanged, machine, "")
	}
}

func (h *Hub) DisconnectMachine(machineID string) {
	h.mu.Lock()
	sids := []string{}
	for sid := range h.machineSIDs[machineID] {
		sids = append(sids, sid)
	}
	delete(h.machineSIDs, machineID)
	h.mu.Unlock()
	for _, sid := range sids {
		h.srv.disconnect(sid)
	}
}

func (h *Hub) SetCachedStatus(machineID string, online bool) {
	h.mu.Lock()
	h.status[machineID] = online
	h.mu.Unlock()
}

func (h *Hub) RemoveCachedStatus(machineID string) {
	h.mu.Lock()
	delete(h.status, machineID)
	h.mu.Unlock()
}

func (h *Hub) LogLines(ctx context.Context, machine core.Doc, lines []string, source string) {
	id := core.IDString(machine["_id"])
	if !h.LogStreamRequested(id) {
		return
	}
	for _, line := range lines {
		h.srv.emit(stcLogStreamLine, map[string]any{"machine_id": id, "source": source, "line": line}, machineLogRoomPrefx+id)
	}
}

// --- machine status monitor (monitor_machine_statuses) ---

func (h *Hub) interval() time.Duration {
	ttl := int(h.app.Cfg.MachineOnlineTTL.Seconds()) / 2
	if ttl == 0 {
		ttl = 5
	}
	return time.Duration(max(5, min(30, ttl))) * time.Second
}

// InitStatusCache mirrors initialize_machine_status_cache.
func (h *Hub) InitStatusCache(ctx context.Context) error {
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = map[string]bool{}
	for _, m := range machines {
		h.status[core.IDString(m["_id"])] = h.app.IsOnline(m)
	}
	return nil
}

// RunStatusMonitor emits status changes, records status events and sends
// Telegram alerts.
func (h *Hub) RunStatusMonitor(ctx context.Context) {
	for {
		h.monitorOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(h.interval()):
		}
	}
}

func (h *Hub) monitorOnce(ctx context.Context) {
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		log.Printf("status monitor: %v", err)
		return
	}
	next := map[string]bool{}
	var changed []core.Doc
	h.mu.Lock()
	for _, m := range machines {
		id := core.IDString(m["_id"])
		online := h.app.IsOnline(m)
		next[id] = online
		if prev, ok := h.status[id]; ok && prev != online {
			changed = append(changed, m)
		}
	}
	h.status = next
	h.mu.Unlock()
	for _, m := range changed {
		h.MachineStatusChanged(ctx, m)
	}
	now := core.Now()
	for _, m := range machines {
		if err := h.syncStatusEvent(ctx, m, next[core.IDString(m["_id"])]); err != nil {
			log.Printf("Failed to process status for machine %v: %v", m["_id"], err)
			continue
		}
		if err := h.app.ProcessStatusAlert(ctx, m, now); err != nil {
			log.Printf("Failed to process status for machine %v: %v", m["_id"], err)
		}
	}
}

func (h *Hub) syncStatusEvent(ctx context.Context, machine core.Doc, online bool) error {
	status := "offline"
	if online {
		status = "online"
	}
	latest, err := h.app.FindOne(ctx, "machine_status_events", bson.M{"machine_id": machine["_id"]},
		options.FindOne().SetSort(core.Sort("changed_at", -1)))
	if err != nil {
		return err
	}
	if latest != nil && core.Str(latest, "status") == status {
		return nil
	}
	_, err = h.app.C("machine_status_events").InsertOne(ctx, bson.D{{Key: "machine_id", Value: machine["_id"]},
		{Key: "user_id", Value: machine["user_id"]}, {Key: "status", Value: status}, {Key: "changed_at", Value: core.Now()}})
	return err
}
