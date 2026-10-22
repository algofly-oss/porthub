// Package auth ports api/shared/sessions.py, api/router/auth/session_utils.py
// and the account endpoints. Sessions live in MongoDB user_sessions with a
// 180-day expiry that slides forward at most once a day.
package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	SessionDays = 180
	renewAfter  = 24 * time.Hour
)

type Sessions struct {
	DB     *mongo.Database
	Cookie string
}

func now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// IsHTTPS mirrors shared.sessions.is_https (direct TLS, proxy header or
// Cloudflare's CF-Visitor).
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	var visitor struct {
		Scheme string `json:"scheme"`
	}
	return json.Unmarshal([]byte(r.Header.Get("CF-Visitor")), &visitor) == nil && visitor.Scheme == "https"
}

func (s *Sessions) SessionCookie(r *http.Request, token string) http.Cookie {
	return http.Cookie{Name: s.Cookie, Value: token, Path: "/", MaxAge: SessionDays * 86400,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: IsHTTPS(r)}
}

func (s *Sessions) ClearCookie() http.Cookie {
	return http.Cookie{Name: s.Cookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0)}
}

func (s *Sessions) Token(r *http.Request) string {
	if c, err := r.Cookie(s.Cookie); err == nil {
		return c.Value
	}
	return ""
}

// UserID returns the user id for a valid session token, or "".
func (s *Sessions) UserID(ctx context.Context, token string) string {
	if token == "" || len(token) > 128 {
		return ""
	}
	var doc struct {
		UserID    string     `bson:"user_id"`
		ExpiresAt *time.Time `bson:"expires_at"`
	}
	err := s.DB.Collection("user_sessions").FindOne(ctx, bson.M{"_id": token, "revoked_at": nil},
		options.FindOne().SetProjection(bson.M{"user_id": 1, "expires_at": 1})).Decode(&doc)
	if err != nil || (doc.ExpiresAt != nil && !doc.ExpiresAt.After(time.Now())) {
		return ""
	}
	return doc.UserID
}

// Start creates a session (create_session_record + expiry) and its cookie.
func (s *Sessions) Start(ctx context.Context, r *http.Request, userID string) (http.Cookie, error) {
	token := uuid.NewString()
	t := now()
	meta := Metadata(r)
	set := bson.M{"user_id": userID, "token": token, "last_accessed_at": t, "revoked_at": nil,
		"expires_at": t.Add(SessionDays * 24 * time.Hour), "renewed_at": t}
	for k, v := range meta {
		set[k] = v
	}
	_, err := s.DB.Collection("user_sessions").UpdateOne(ctx, bson.M{"_id": token},
		bson.M{"$set": set, "$setOnInsert": bson.M{"created_at": t}}, options.UpdateOne().SetUpsert(true))
	return s.SessionCookie(r, token), err
}

func (s *Sessions) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.DB.Collection("user_sessions").UpdateOne(ctx, bson.M{"_id": token}, bson.M{"$set": bson.M{"revoked_at": now()}})
	return err
}

func (s *Sessions) RevokeUser(ctx context.Context, userID string) error {
	_, err := s.DB.Collection("user_sessions").UpdateMany(ctx, bson.M{"user_id": userID, "revoked_at": nil}, bson.M{"$set": bson.M{"revoked_at": now()}})
	return err
}

// Touch mirrors touch_session_record: refresh device metadata (not the IP)
// and the last access time. Returns the number of matched sessions.
func (s *Sessions) Touch(ctx context.Context, r *http.Request, token string) int64 {
	if token == "" {
		return 0
	}
	meta := Metadata(r)
	delete(meta, "ip")
	meta["last_accessed_at"] = now()
	res, err := s.DB.Collection("user_sessions").UpdateOne(ctx, bson.M{"_id": token, "revoked_at": nil}, bson.M{"$set": meta})
	if err != nil {
		return 0
	}
	return res.MatchedCount
}

// Record mirrors create_session_record for a session found only by token.
func (s *Sessions) Record(ctx context.Context, r *http.Request, userID, token string) {
	t := now()
	set := bson.M{"user_id": userID, "token": token, "last_accessed_at": t, "revoked_at": nil}
	for k, v := range Metadata(r) {
		set[k] = v
	}
	_, _ = s.DB.Collection("user_sessions").UpdateOne(ctx, bson.M{"_id": token},
		bson.M{"$set": set, "$setOnInsert": bson.M{"created_at": t}}, options.UpdateOne().SetUpsert(true))
}

// RenewMiddleware slides the session expiry at most once a day for
// successful requests (shared.sessions.renew_if_due).
func (s *Sessions) RenewMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.Token(r)
		if token == "" || len(token) > 128 {
			next.ServeHTTP(w, r)
			return
		}
		rw := &renewWriter{ResponseWriter: w, renew: func() {
			t := now()
			filter := bson.M{"_id": token, "revoked_at": nil, "$and": bson.A{
				bson.M{"$or": bson.A{bson.M{"expires_at": nil}, bson.M{"expires_at": bson.M{"$exists": false}}, bson.M{"expires_at": bson.M{"$gt": t}}}},
				bson.M{"$or": bson.A{bson.M{"renewed_at": bson.M{"$exists": false}}, bson.M{"renewed_at": bson.M{"$lt": t.Add(-renewAfter)}}}},
			}}
			res, err := s.DB.Collection("user_sessions").UpdateOne(r.Context(), filter,
				bson.M{"$set": bson.M{"renewed_at": t, "expires_at": t.Add(SessionDays * 24 * time.Hour)}})
			if err == nil && res.MatchedCount == 1 {
				c := s.SessionCookie(r, token)
				http.SetCookie(w, &c)
			}
		}}
		next.ServeHTTP(rw, r)
	})
}

type renewWriter struct {
	http.ResponseWriter
	renew func()
	done  bool
}

func (w *renewWriter) WriteHeader(code int) {
	if !w.done {
		w.done = true
		if code < 400 {
			w.renew()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *renewWriter) Write(b []byte) (int, error) {
	if !w.done {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *renewWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *renewWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// --- session metadata (router/auth/session_utils.py) ---

func publicIP(v string) bool {
	ip := net.ParseIP(v)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func ClientIP(r *http.Request) string {
	var candidates []string
	for _, h := range []string{"Cf-Connecting-Ip", "X-Real-Ip", "X-Client-Ip", "X-Forwarded-For"} {
		for _, part := range strings.Split(r.Header.Get(h), ",") {
			if p := strings.TrimSpace(part); p != "" {
				candidates = append(candidates, p)
			}
		}
	}
	for _, c := range candidates {
		if publicIP(c) {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var mobileRE = regexp.MustCompile(`Mobile|iPhone|Android`)

func Metadata(r *http.Request) bson.M {
	ua := r.Header.Get("User-Agent")
	browser := "Unknown browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Chromium/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		browser = "Safari"
	}
	osName := "Unknown OS"
	switch {
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		osName = "iOS"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	device := "Desktop"
	if mobileRE.MatchString(ua) {
		device = "Mobile"
	} else if strings.Contains(ua, "iPad") || strings.Contains(ua, "Tablet") {
		device = "Tablet"
	}
	return bson.M{"browser": browser, "os": osName, "device_type": device, "device_name": browser + " on " + osName,
		"ip": ClientIP(r), "user_agent": ua}
}
