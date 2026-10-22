package auth

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/algofly-oss/porthub/server/internal/config"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/store"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Handlers struct {
	DB       *mongo.Database
	Config   config.Config
	Sessions *Sessions
}

type Message struct {
	Body struct {
		Msg string `json:"msg"`
	}
}

func msg(text string) *Message {
	m := &Message{}
	m.Body.Msg = text
	return m
}

type MessageWithCookie struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Msg string `json:"msg"`
	}
}

func withCookie(text string, cookies ...http.Cookie) *MessageWithCookie {
	m := &MessageWithCookie{SetCookie: cookies}
	m.Body.Msg = text
	return m
}

type Credentials struct {
	Body struct {
		Username string `json:"username" doc:"Email or phone of the user"`
		Password string `json:"password"`
	}
}

type user struct {
	ID             bson.ObjectID `bson:"_id"`
	Name           string        `bson:"name"`
	Username       string        `bson:"username"`
	Email          string        `bson:"email"`
	Role           string        `bson:"role"`
	Password       []byte        `bson:"password"`
	CreatedAt      time.Time     `bson:"created_at"`
	ProfilePicture any           `bson:"profile_picture"`
	Preferences    struct {
		NavCollapsed bool `bson:"nav_collapsed"`
	} `bson:"preferences"`
}

func (h *Handlers) users() *mongo.Collection { return h.DB.Collection("users") }

// currentUserID mirrors authenticate_user: 400 "User not logged in".
func (h *Handlers) currentUserID(ctx context.Context) (string, error) {
	r := httpapi.Request(ctx)
	id := h.Sessions.UserID(ctx, h.Sessions.Token(r))
	if id == "" {
		return "", httpapi.Fail(400, "User not logged in")
	}
	return id, nil
}

var passwordRE = regexp.MustCompile(`^.{8,}$`)

// strongPassword mirrors the Python lookahead regex (Go RE2 has none):
// at least 8 chars with a digit, lower, upper and a symbol.
func strongPassword(p string) bool {
	if !passwordRE.MatchString(p) {
		return false
	}
	var digit, lower, upper, symbol bool
	for _, c := range p {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		default:
			symbol = true
		}
	}
	return digit && lower && upper && symbol
}

func Register(api huma.API, h *Handlers) {
	tag := []string{"Authentication"}

	huma.Register(api, huma.Operation{OperationID: "ping", Method: http.MethodGet, Path: "/api/ping", Summary: "Ping", Tags: []string{"Ping"}},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Msg     string `json:"msg"`
				Latency string `json:"latency"`
			}
		}, error) {
			// Same as the Python route: measures outbound reachability.
			start := time.Now()
			client := &http.Client{Timeout: 10 * time.Second}
			if resp, err := client.Get("https://google.com"); err == nil {
				resp.Body.Close()
			}
			out := &struct {
				Body struct {
					Msg     string `json:"msg"`
					Latency string `json:"latency"`
				}
			}{}
			out.Body.Msg = "pong"
			out.Body.Latency = formatMS(time.Since(start))
			return out, nil
		})

	type settingsOut struct {
		Body struct {
			SignupDisabled       bool   `json:"signup_disabled"`
			SignupEnabled        bool   `json:"signup_enabled"`
			WebProxyDomainSuffix string `json:"web_proxy_domain_suffix"`
			ServiceDomain        string `json:"port_hub_service_domain"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "auth-settings", Method: http.MethodGet, Path: "/api/auth/settings", Summary: "Auth Settings", Tags: tag},
		func(ctx context.Context, _ *struct{}) (*settingsOut, error) {
			out := &settingsOut{}
			out.Body.SignupDisabled = h.Config.SignupDisabled
			out.Body.SignupEnabled = !h.Config.SignupDisabled
			out.Body.WebProxyDomainSuffix = h.Config.WebProxyDomainSuffix
			out.Body.ServiceDomain = h.Config.ServiceDomain
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "signin", Method: http.MethodPost, Path: "/api/auth/signin", Summary: "Sign in a user", Tags: tag},
		func(ctx context.Context, in *Credentials) (*MessageWithCookie, error) {
			r := httpapi.Request(ctx)
			if h.Sessions.UserID(ctx, h.Sessions.Token(r)) != "" {
				return withCookie("success"), nil
			}
			var u user
			if err := h.users().FindOne(ctx, bson.M{"username": in.Body.Username}).Decode(&u); err != nil {
				return nil, httpapi.Fail(400, "incorrect username")
			}
			if bcrypt.CompareHashAndPassword(u.Password, []byte(in.Body.Password)) != nil {
				return nil, httpapi.Fail(400, "incorrect password")
			}
			cookie, err := h.Sessions.Start(ctx, r, u.ID.Hex())
			if err != nil {
				return nil, err
			}
			return withCookie("success", cookie), nil
		})

	huma.Register(api, huma.Operation{OperationID: "signout", Method: http.MethodPost, Path: "/api/auth/signout", Summary: "Signout", Tags: tag},
		func(ctx context.Context, _ *struct{}) (*MessageWithCookie, error) {
			r := httpapi.Request(ctx)
			token := h.Sessions.Token(r)
			if token == "" {
				return withCookie("user not logged in"), nil
			}
			if err := h.Sessions.Revoke(ctx, token); err != nil {
				return nil, err
			}
			return withCookie("success", h.Sessions.ClearCookie()), nil
		})

	type userOut struct {
		Body map[string]any
	}
	serialize := func(u user) map[string]any {
		email := u.Email
		if email == "" {
			email = u.Username
		}
		return map[string]any{"name": u.Name, "username": u.Username, "email": email, "role": u.Role,
			"created_at": store.PyTime(u.CreatedAt), "profile_picture": store.JSON(u.ProfilePicture),
			"has_password": len(u.Password) > 0, "preferences": map[string]any{"nav_collapsed": u.Preferences.NavCollapsed}}
	}
	huma.Register(api, huma.Operation{OperationID: "account-info", Method: http.MethodGet, Path: "/api/auth/me", Summary: "Account Info", Tags: tag},
		func(ctx context.Context, _ *struct{}) (*userOut, error) {
			id, err := h.currentUserID(ctx)
			if err != nil {
				return nil, err
			}
			r := httpapi.Request(ctx)
			if token := h.Sessions.Token(r); h.Sessions.Touch(ctx, r, token) == 0 {
				h.Sessions.Record(ctx, r, id, token)
			}
			oid, err := bson.ObjectIDFromHex(id)
			var u user
			if err != nil || h.users().FindOne(ctx, bson.M{"_id": oid}).Decode(&u) != nil {
				return nil, httpapi.Fail(400, "User not logged in")
			}
			return &userOut{Body: serialize(u)}, nil
		})

	type sessionsOut struct {
		Body struct {
			Data []map[string]any `json:"data"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "list-sessions", Method: http.MethodGet, Path: "/api/auth/sessions", Summary: "List Sessions", Tags: tag},
		func(ctx context.Context, _ *struct{}) (*sessionsOut, error) {
			id, err := h.currentUserID(ctx)
			if err != nil {
				return nil, err
			}
			r := httpapi.Request(ctx)
			token := h.Sessions.Token(r)
			if h.Sessions.Touch(ctx, r, token) == 0 {
				h.Sessions.Record(ctx, r, id, token)
			}
			cur, err := h.DB.Collection("user_sessions").Find(ctx, bson.M{"user_id": id, "revoked_at": nil},
				options.Find().SetSort(bson.M{"last_accessed_at": -1}).SetLimit(100))
			if err != nil {
				return nil, err
			}
			var docs []bson.M
			if err = cur.All(ctx, &docs); err != nil {
				return nil, err
			}
			out := &sessionsOut{}
			out.Body.Data = []map[string]any{}
			for _, d := range docs {
				out.Body.Data = append(out.Body.Data, serializeSession(d, token))
			}
			return out, nil
		})

	type sessionPath struct {
		SessionID string `path:"session_id"`
	}
	huma.Register(api, huma.Operation{OperationID: "revoke-session", Method: http.MethodDelete, Path: "/api/auth/sessions/{session_id}", Summary: "Revoke Session", Tags: tag},
		func(ctx context.Context, in *sessionPath) (*MessageWithCookie, error) {
			id, err := h.currentUserID(ctx)
			if err != nil {
				return nil, err
			}
			n, err := h.DB.Collection("user_sessions").CountDocuments(ctx, bson.M{"_id": in.SessionID, "user_id": id, "revoked_at": nil})
			if err != nil || n == 0 {
				return nil, httpapi.Fail(404, "Session not found")
			}
			if err = h.Sessions.Revoke(ctx, in.SessionID); err != nil {
				return nil, err
			}
			if in.SessionID == h.Sessions.Token(httpapi.Request(ctx)) {
				return withCookie("success", h.Sessions.ClearCookie()), nil
			}
			return withCookie("success"), nil
		})

	type passwordIn struct {
		Body struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
	}
	huma.Register(api, huma.Operation{OperationID: "update-password", Method: http.MethodPut, Path: "/api/auth/settings/password", Summary: "Update Password", Tags: tag},
		func(ctx context.Context, in *passwordIn) (*Message, error) {
			id, err := h.currentUserID(ctx)
			if err != nil {
				return nil, err
			}
			oid, _ := bson.ObjectIDFromHex(id)
			var u user
			if h.users().FindOne(ctx, bson.M{"_id": oid}).Decode(&u) != nil {
				return nil, httpapi.Fail(400, "User not logged in")
			}
			if bcrypt.CompareHashAndPassword(u.Password, []byte(in.Body.CurrentPassword)) != nil {
				return nil, httpapi.Fail(400, "Current password is incorrect")
			}
			if in.Body.CurrentPassword == in.Body.NewPassword {
				return nil, httpapi.Fail(400, "New password must be different from the current password")
			}
			if !strongPassword(in.Body.NewPassword) {
				return nil, httpapi.Fail(400, "New password must include uppercase, lowercase, number, and symbol")
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(in.Body.NewPassword), 12)
			if err != nil {
				return nil, err
			}
			// Same stored shape as Python bcrypt: hash bytes (salt is embedded).
			_, err = h.users().UpdateOne(ctx, bson.M{"_id": u.ID}, bson.M{"$set": bson.M{"password": hash, "salt": hash[:29]}})
			if err != nil {
				return nil, err
			}
			return msg("password updated"), nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-account", Method: http.MethodDelete, Path: "/api/auth/delete", Summary: "Delete Account", Tags: tag},
		func(ctx context.Context, in *Credentials) (*MessageWithCookie, error) {
			var u user
			if h.users().FindOne(ctx, bson.M{"username": in.Body.Username}).Decode(&u) != nil {
				return nil, httpapi.Fail(400, "Username does not exist")
			}
			if bcrypt.CompareHashAndPassword(u.Password, []byte(in.Body.Password)) != nil {
				return nil, httpapi.Fail(400, "Password is incorrect")
			}
			if _, err := h.users().DeleteOne(ctx, bson.M{"_id": u.ID}); err != nil {
				return nil, err
			}
			// A deleted account must not keep any signed-in device.
			if err := h.Sessions.RevokeUser(ctx, u.ID.Hex()); err != nil {
				return nil, err
			}
			return withCookie("user deleted", h.Sessions.ClearCookie()), nil
		})
}

func formatMS(d time.Duration) string {
	return strconvFormat(float64(d.Nanoseconds())/1e6) + " ms"
}

func serializeSession(d bson.M, current string) map[string]any {
	str := func(key, fallback string) string {
		if v, ok := d[key].(string); ok && v != "" {
			return v
		}
		return fallback
	}
	when := func(key string) any {
		if v, ok := d[key].(bson.DateTime); ok {
			return store.PyTime(v.Time()) + "Z"
		}
		return nil
	}
	id, _ := d["_id"].(string)
	return map[string]any{"id": d["_id"], "device_name": str("device_name", "Unknown device"), "device_type": str("device_type", "Unknown"),
		"browser": str("browser", "Unknown browser"), "os": str("os", "Unknown OS"), "ip": str("ip", "Unknown IP"),
		"created_at": when("created_at"), "last_accessed_at": when("last_accessed_at"), "current": id == current}
}

func strconvFormat(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }
