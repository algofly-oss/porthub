package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openDB opens the service database with one connection: every read and
// write is serialized, like the single Python worker. busy_timeout matches
// sqlite3's default 5 s timeout.
func openDB(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// initDB creates and migrates the schema exactly like init_db.
func initDB(ctx context.Context, db *sql.DB) error {
	stmts := []string{`
            CREATE TABLE IF NOT EXISTS port_policies (
                port INTEGER PRIMARY KEY,
                is_public INTEGER NOT NULL DEFAULT 1,
                allowed_ips TEXT NOT NULL DEFAULT '[]',
                updated_at INTEGER NOT NULL
            )
            `, `
            CREATE TABLE IF NOT EXISTS traffic_buffer (
                port INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                in_bytes INTEGER NOT NULL,
                out_bytes INTEGER NOT NULL,
                drop_bytes INTEGER NOT NULL DEFAULT 0,
                blocked_ips TEXT NOT NULL DEFAULT '[]',
                incoming_ips TEXT NOT NULL DEFAULT '[]',
                outgoing_ips TEXT NOT NULL DEFAULT '[]'
            )
            `}
	for _, q := range stmts {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(traffic_buffer)")
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, typ, notNull, def, pk any
		var name string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []struct{ name, def string }{
		{"drop_bytes", "INTEGER NOT NULL DEFAULT 0"},
		{"blocked_ips", "TEXT NOT NULL DEFAULT '[]'"},
		{"incoming_ips", "TEXT NOT NULL DEFAULT '[]'"},
		{"outgoing_ips", "TEXT NOT NULL DEFAULT '[]'"},
	} {
		if !columns[col.name] {
			if _, err := db.ExecContext(ctx, "ALTER TABLE traffic_buffer ADD COLUMN "+col.name+" "+col.def); err != nil {
				return err
			}
		}
	}
	for _, q := range []string{`
            CREATE TABLE IF NOT EXISTS active_ports (
                port INTEGER PRIMARY KEY,
                last_seen INTEGER NOT NULL
            )
            `, `
            CREATE TABLE IF NOT EXISTS recent_ip_hits (
                port INTEGER NOT NULL,
                ip TEXT NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (port, ip)
            )
            `} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	// Compatibility with the original sample schema.
	var name string
	err = db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'allowlists'`).Scan(&name)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
                INSERT OR IGNORE INTO port_policies (port, is_public, allowed_ips, updated_at)
                SELECT port, 0, ips, strftime('%s', 'now')
                FROM allowlists
                `)
	return err
}

// loadState reads port_policies like load_state.
func loadState(ctx context.Context, db *sql.DB) (map[int64]Policy, error) {
	rows, err := db.QueryContext(ctx, `SELECT port, is_public, allowed_ips FROM port_policies ORDER BY port ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	state := map[int64]Policy{}
	for rows.Next() {
		var port int64
		var isPublic, allowed any
		if err := rows.Scan(&port, &isPublic, &allowed); err != nil {
			return nil, err
		}
		ips, err := decodeAllowedIPs(allowed)
		if err != nil {
			return nil, fmt.Errorf("port_policies port %d: %w", port, err)
		}
		state[port] = Policy{IsPublic: pyTruthy(isPublic), AllowedIPs: ips}
	}
	return state, rows.Err()
}

// decodeAllowedIPs is list(json.loads(allowed_ips or "[]") or []).
func decodeAllowedIPs(v any) ([]string, error) {
	var text string
	switch x := v.(type) {
	case string:
		text = x
	case []byte:
		text = string(x)
	}
	if text == "" {
		text = "[]"
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return nil, err
	}
	out := []string{}
	list, _ := decoded.([]any)
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(item))
		}
	}
	return out, nil
}

func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case int64:
		return x != 0
	case float64:
		return x != 0
	case bool:
		return x
	case string:
		return x != ""
	case []byte:
		return len(x) > 0
	}
	return true
}

const trimRecentSQL = `
        DELETE FROM recent_ip_hits
        WHERE rowid IN (
            SELECT rowid
            FROM recent_ip_hits
            WHERE port = ?
            ORDER BY last_seen DESC, ip ASC
            LIMIT -1 OFFSET ?
        )
        `

const upsertRecentSQL = `
                INSERT INTO recent_ip_hits (port, ip, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(port, ip) DO UPDATE SET last_seen = excluded.last_seen
                `

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *Service) trimRecentIPHistory(ctx context.Context, db execer, port int64) error {
	_, err := db.ExecContext(ctx, trimRecentSQL, port, s.cfg.RecentIPHistoryLimit)
	return err
}

// writeBatch persists one db_writer batch in one transaction.
func (s *Service) writeBatch(ctx context.Context, batch []pendingRow, recent []recentRow, tracked []int64, pruneBefore int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range batch {
		if _, err := tx.ExecContext(ctx, `
                INSERT INTO traffic_buffer (
                    port,
                    ts,
                    in_bytes,
                    out_bytes,
                    drop_bytes,
                    blocked_ips,
                    incoming_ips,
                    outgoing_ips
                )
                VALUES (?,?,?,?,?,?,?,?)
                `, r.port, r.ts, r.in, r.out, r.drop, r.blocked, r.incoming, r.outgoing); err != nil {
			return err
		}
	}
	for _, r := range batch {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO active_ports (port, last_seen) VALUES (?, ?)", r.port, r.ts); err != nil {
			return err
		}
	}
	if len(recent) > 0 {
		for _, r := range recent {
			if _, err := tx.ExecContext(ctx, upsertRecentSQL, r.port, r.ip, r.lastSeen); err != nil {
				return err
			}
		}
		for _, port := range tracked {
			if err := s.trimRecentIPHistory(ctx, tx, port); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM traffic_buffer WHERE ts < ?", pruneBefore); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM active_ports WHERE last_seen < ?", pruneBefore); err != nil {
		return err
	}
	return tx.Commit()
}

type recentRow struct {
	port     int64
	ip       string
	lastSeen int64
}
