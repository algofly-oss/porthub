// Package account ports the remaining account routes (router/auth signup,
// account_update, telegram_settings) and the admin overview.
package account

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type h struct{ app *core.App }

type anyBody struct{ Body map[string]any }

func body(m map[string]any) *anyBody { return &anyBody{Body: m} }

// passwordHash reads the stored bcrypt hash (bytes in Python, Binary in BSON).
func passwordHash(v any) []byte {
	switch x := v.(type) {
	case bson.Binary:
		return x.Data
	case []byte:
		return x
	case string:
		return []byte(x)
	}
	return nil
}

func checkPassword(user core.Doc, password string) bool {
	hash := passwordHash(user["password"])
	return len(hash) > 0 && bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func hashPassword(password string) (bson.M, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, httpapi.Fail(400, "Password must be at most 72 bytes")
	}
	// Same stored shape as Python bcrypt: hash bytes plus the embedded salt.
	return bson.M{"password": hash, "salt": hash[:29]}, nil
}

// currentUser mirrors _user_object_id + find_one: 400 when missing.
func (h *h) currentUser(ctx context.Context) (core.Doc, error) {
	return h.app.User(ctx)
}

func Register(api huma.API, app *core.App) {
	h := &h{app: app}
	tag := []string{"Authentication"}
	huma.Register(api, huma.Operation{OperationID: "signup", Method: http.MethodPost, Path: "/api/auth/signup", Summary: "Signup", Tags: tag}, h.signup)
	huma.Register(api, huma.Operation{OperationID: "update-preferences", Method: http.MethodPatch, Path: "/api/auth/preferences", Summary: "Update Preferences", Tags: tag}, h.preferences)
	huma.Register(api, huma.Operation{OperationID: "update-account", Method: http.MethodPatch, Path: "/api/auth/account", Summary: "Update Account", Tags: tag}, h.updateAccount)
	huma.Register(api, huma.Operation{OperationID: "update-account-password", Method: http.MethodPatch, Path: "/api/auth/password", Summary: "Update Account Password", Tags: tag}, h.updatePassword)
	huma.Register(api, huma.Operation{OperationID: "get-telegram-settings", Method: http.MethodGet, Path: "/api/auth/telegram", Summary: "Get Telegram Settings", Tags: tag}, h.getTelegram)
	huma.Register(api, huma.Operation{OperationID: "update-telegram-settings", Method: http.MethodPatch, Path: "/api/auth/telegram", Summary: "Update Telegram Settings", Tags: tag}, h.updateTelegram)
	huma.Register(api, huma.Operation{OperationID: "send-test-telegram-message", Method: http.MethodPost, Path: "/api/auth/telegram/test", Summary: "Send Test Telegram Message", Tags: tag}, h.testTelegram)
	huma.Register(api, huma.Operation{OperationID: "get-platform-overview", Method: http.MethodGet, Path: "/api/admin/overview", Summary: "Get Platform Overview", Tags: []string{"Admin"}}, h.adminOverview)
}

// --- signup ---

type signupIn struct {
	Body struct {
		Name            string  `json:"name"`
		Username        string  `json:"username"`
		Password        string  `json:"password"`
		InvitationToken *string `json:"invitation_token,omitempty" required:"false"`
	}
}

type signupOut struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      map[string]any
}

func (h *h) signup(ctx context.Context, in *signupIn) (*signupOut, error) {
	app, b := h.app, in.Body
	token := ""
	if b.InvitationToken != nil {
		token = *b.InvitationToken
	}
	if token != "" {
		invite, err := app.ValidInvitation(ctx, token)
		if err != nil {
			return nil, err
		}
		email := core.Str(invite, "email")
		if strings.ToLower(strings.TrimSpace(b.Username)) != email {
			return nil, httpapi.Fail(403, "Use the email address on the invitation")
		}
		if n := len(b.Password); strings.TrimSpace(b.Name) == "" || len([]rune(b.Name)) > 100 || n < 12 || n > 72 {
			return nil, httpapi.Fail(400, "Provide a name and a password between 12 and 72 bytes")
		}
		b.Username = email
		existing, err := app.FindOne(ctx, "users", bson.M{"username": bson.M{"$regex": "^" + regexp.QuoteMeta(b.Username) + "$", "$options": "i"}})
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, httpapi.Fail(409, "An account already exists. Sign in to accept the invitation.")
		}
		// Required to make concurrent invited signups atomic.
		if _, err := app.C("users").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)}); err != nil {
			return nil, httpapi.Fail(409, "An administrator must resolve duplicate account names before invited registration")
		}
	}
	if app.Cfg.SignupDisabled && token == "" {
		return nil, httpapi.Fail(403, "sign up is disabled")
	}
	if existing, err := app.FindOne(ctx, "users", bson.M{"username": b.Username}); err != nil {
		return nil, err
	} else if existing != nil {
		return &signupOut{Body: map[string]any{"msg": "user already exists"}}, nil
	}
	pw, err := hashPassword(b.Password)
	if err != nil {
		return nil, err
	}
	if _, err := app.C("users").InsertOne(ctx, bson.D{{Key: "name", Value: b.Name}, {Key: "username", Value: b.Username},
		{Key: "password", Value: pw["password"]}, {Key: "role", Value: "user"}, {Key: "salt", Value: pw["salt"]}, {Key: "created_at", Value: core.Now()}}); err != nil {
		return nil, err
	}
	user, err := app.FindOne(ctx, "users", bson.M{"username": b.Username})
	if err != nil || user == nil {
		return nil, fmt.Errorf("created user not found: %v", err)
	}
	out := map[string]any{"msg": "success"}
	if token != "" {
		workspace, err := app.AcceptInvitation(ctx, user, token)
		if err != nil {
			return nil, err
		}
		if workspace != "" {
			out["workspace_id"] = workspace
		}
	}
	cookie, err := app.Sessions.Start(ctx, httpapi.Request(ctx), core.IDString(user["_id"]))
	if err != nil {
		return nil, err
	}
	return &signupOut{SetCookie: []http.Cookie{cookie}, Body: out}, nil
}

// --- account_update ---

type preferencesIn struct {
	Body struct {
		NavCollapsed bool `json:"nav_collapsed"`
	}
}

func (h *h) preferences(ctx context.Context, in *preferencesIn) (*anyBody, error) {
	id, err := h.app.UserID(ctx)
	if err != nil {
		return nil, err
	}
	oid, _ := bson.ObjectIDFromHex(id)
	res, err := h.app.C("users").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"preferences.nav_collapsed": in.Body.NavCollapsed}})
	if err != nil {
		return nil, err
	}
	if res.MatchedCount == 0 {
		return nil, httpapi.Fail(404, "User not found")
	}
	return body(map[string]any{"nav_collapsed": in.Body.NavCollapsed}), nil
}

func serializeUser(user core.Doc) map[string]any {
	email := user["email"]
	if !core.Truthy(user, "email") {
		email = user["username"]
	}
	nav := any(false)
	if prefs, ok := core.Map(user, "preferences"); ok {
		nav = core.Get(prefs, "nav_collapsed", false)
	}
	return map[string]any{
		"name": core.JSON(user["name"]), "username": core.JSON(user["username"]), "email": core.JSON(email),
		"role": core.JSON(user["role"]), "created_at": core.JSON(user["created_at"]), "profile_picture": core.JSON(user["profile_picture"]),
		"has_password": len(passwordHash(user["password"])) > 0, "preferences": map[string]any{"nav_collapsed": nav},
	}
}

type profilePicture struct {
	DataURL     string  `json:"data_url"`
	Filename    *string `json:"filename,omitempty" required:"false"`
	ContentType *string `json:"content_type,omitempty" required:"false"`
	Size        *int    `json:"size,omitempty" required:"false"`
}

type accountIn struct {
	Body struct {
		Name                 *string         `json:"name,omitempty" required:"false"`
		Email                *string         `json:"email,omitempty" required:"false"`
		CurrentPassword      *string         `json:"current_password,omitempty" required:"false"`
		ProfilePicture       *profilePicture `json:"profile_picture,omitempty" required:"false"`
		RemoveProfilePicture bool            `json:"remove_profile_picture,omitempty" required:"false"`
	}
}

var (
	dataURLRE = regexp.MustCompile(`^data:([-\w.]+/[-\w.+]+);base64,(.+)$`)
	emailRE   = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

const maxPictureBytes = 2 * 1024 * 1024

func normalizePicture(p *profilePicture) (bson.M, error) {
	dataURL := strings.TrimSpace(p.DataURL)
	m := dataURLRE.FindStringSubmatch(dataURL)
	if m == nil {
		return nil, httpapi.Fail(400, "Profile picture must be an image")
	}
	ct := strings.ToLower(m[1])
	if ct == "image/jpg" {
		ct = "image/jpeg"
	}
	if ct != "image/png" && ct != "image/jpeg" && ct != "image/webp" {
		return nil, httpapi.Fail(400, "Profile picture must be a PNG, JPG, or WebP image")
	}
	img, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		return nil, httpapi.Fail(400, "Profile picture could not be read")
	}
	if len(img) == 0 {
		return nil, httpapi.Fail(400, "Profile picture is empty")
	}
	if len(img) > maxPictureBytes {
		return nil, httpapi.Fail(400, "Profile picture must be 2 MB or smaller")
	}
	name := ""
	if p.Filename != nil {
		name = strings.TrimSpace(*p.Filename)
		if r := []rune(name); len(r) > 160 {
			name = string(r[:160])
		}
	}
	return bson.M{"data_url": dataURL, "content_type": ct, "filename": name, "size": len(img), "updated_at": core.Now()}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (h *h) updateAccount(ctx context.Context, in *accountIn) (*anyBody, error) {
	app, b := h.app, in.Body
	user, err := h.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	id := user["_id"]
	set, unset := bson.M{}, bson.M{}
	name := strings.TrimSpace(deref(b.Name))
	email := strings.ToLower(strings.TrimSpace(deref(b.Email)))
	current := core.Str(user, "email")
	if current == "" {
		current = core.Str(user, "username")
	}
	current = strings.ToLower(current)
	if name != "" && name != core.Str(user, "name") {
		set["name"] = name
	}
	if email != "" && email != current {
		if !emailRE.MatchString(email) {
			return nil, httpapi.Fail(400, "Enter a valid email address")
		}
		if deref(b.CurrentPassword) == "" {
			return nil, httpapi.Fail(400, "Current password required")
		}
		if !checkPassword(user, *b.CurrentPassword) {
			return nil, httpapi.Fail(400, "Incorrect password")
		}
		existing, err := app.FindOne(ctx, "users", bson.M{"_id": bson.M{"$ne": id}, "$or": bson.A{bson.M{"username": email}, bson.M{"email": email}}})
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, httpapi.Fail(400, "Email already exists")
		}
		set["username"], set["email"] = email, email
	}
	if b.ProfilePicture != nil {
		pic, err := normalizePicture(b.ProfilePicture)
		if err != nil {
			return nil, err
		}
		set["profile_picture"] = pic
	} else if b.RemoveProfilePicture {
		unset["profile_picture"] = ""
	}
	if len(set) > 0 || len(unset) > 0 {
		op := bson.M{}
		if len(set) > 0 {
			op["$set"] = set
		}
		if len(unset) > 0 {
			op["$unset"] = unset
		}
		if _, err := app.C("users").UpdateOne(ctx, bson.M{"_id": id}, op); err != nil {
			if mongo.IsDuplicateKeyError(err) {
				return nil, httpapi.Fail(400, "Email already exists")
			}
			return nil, err
		}
	}
	updated, err := app.FindOne(ctx, "users", bson.M{"_id": id})
	if err != nil {
		return nil, err
	}
	return body(serializeUser(updated)), nil
}

type accountPasswordIn struct {
	Body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
}

func (h *h) updatePassword(ctx context.Context, in *accountPasswordIn) (*anyBody, error) {
	user, err := h.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	if in.Body.CurrentPassword == "" {
		return nil, httpapi.Fail(400, "Current password required")
	}
	if !checkPassword(user, in.Body.CurrentPassword) {
		return nil, httpapi.Fail(400, "Incorrect password")
	}
	if len([]rune(in.Body.NewPassword)) < 8 {
		return nil, httpapi.Fail(400, "Password must be at least 8 characters")
	}
	pw, err := hashPassword(in.Body.NewPassword)
	if err != nil {
		return nil, err
	}
	if _, err := h.app.C("users").UpdateOne(ctx, bson.M{"_id": user["_id"]}, bson.M{"$set": pw}); err != nil {
		return nil, err
	}
	return body(map[string]any{"msg": "success", "has_password": true}), nil
}

// --- telegram_settings ---

func maskToken(token string) string {
	token = strings.TrimSpace(token)
	n := len([]rune(token))
	if n == 0 {
		return ""
	}
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	r := []rune(token)
	return strings.Repeat("*", n-4) + string(r[n-4:])
}

func serializeTelegram(user core.Doc) map[string]any {
	c := core.UserTelegramConfig(user)
	chats := any(core.List(user, "telegram_chat_ids"))
	if !core.Truthy(user, "telegram_chat_ids") {
		chats = []any{}
	}
	return map[string]any{
		"bot_token_masked":       maskToken(core.Str(user, "telegram_bot_token")),
		"has_bot_token":          core.Truthy(user, "telegram_bot_token"),
		"chat_ids":               core.JSON(chats),
		"alerts_enabled":         c.AlertsEnabled,
		"instant_alerts_enabled": c.InstantEnabled,
		"digest_enabled":         c.DigestEnabled,
		"digest_interval_hours":  c.DigestIntervalHours,
	}
}

func (h *h) getTelegram(ctx context.Context, _ *struct{}) (*anyBody, error) {
	user, err := h.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	return body(serializeTelegram(user)), nil
}

type telegramIn struct {
	Body struct {
		BotToken             *string   `json:"bot_token,omitempty" required:"false"`
		ChatIDs              *[]string `json:"chat_ids,omitempty" required:"false"`
		AlertsEnabled        *bool     `json:"alerts_enabled,omitempty" required:"false"`
		InstantAlertsEnabled *bool     `json:"instant_alerts_enabled,omitempty" required:"false"`
		DigestEnabled        *bool     `json:"digest_enabled,omitempty" required:"false"`
		DigestIntervalHours  *int      `json:"digest_interval_hours,omitempty" required:"false"`
	}
}

func (h *h) updateTelegram(ctx context.Context, in *telegramIn) (*anyBody, error) {
	user, err := h.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	b, set := in.Body, bson.M{}
	if b.BotToken != nil {
		set["telegram_bot_token"] = strings.TrimSpace(*b.BotToken)
	}
	if b.ChatIDs != nil {
		chats := []string{}
		for _, id := range *b.ChatIDs {
			if s := strings.TrimSpace(id); s != "" {
				chats = append(chats, s)
			}
		}
		if len(chats) > 20 {
			return nil, httpapi.Fail(400, "You can configure at most 20 chat/channel IDs")
		}
		set["telegram_chat_ids"] = chats
	}
	if b.AlertsEnabled != nil {
		set["telegram_alerts_enabled"] = *b.AlertsEnabled
	}
	if b.InstantAlertsEnabled != nil {
		set["telegram_instant_alerts_enabled"] = *b.InstantAlertsEnabled
	}
	if b.DigestEnabled != nil {
		set["telegram_digest_enabled"] = *b.DigestEnabled
	}
	if b.DigestIntervalHours != nil {
		switch *b.DigestIntervalHours {
		case 1, 3, 6, 12, 24:
			set["telegram_digest_interval_hours"] = *b.DigestIntervalHours
		default:
			return nil, httpapi.Fail(400, "Digest interval must be one of 1, 3, 6, 12, or 24 hours")
		}
	}
	if len(set) > 0 {
		if _, err := h.app.C("users").UpdateOne(ctx, bson.M{"_id": user["_id"]}, bson.M{"$set": set}); err != nil {
			return nil, err
		}
	}
	updated, err := h.app.FindOne(ctx, "users", bson.M{"_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	return body(serializeTelegram(updated)), nil
}

func (h *h) testTelegram(ctx context.Context, _ *struct{}) (*anyBody, error) {
	user, err := h.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	token := core.Trim(user, "telegram_bot_token")
	chats := core.List(user, "telegram_chat_ids")
	if token == "" || len(chats) == 0 {
		return nil, httpapi.Fail(400, "Add a bot token and at least one chat ID before sending a test message")
	}
	result := core.SendTelegram(ctx, token, chats, "✅ PortHub Telegram alerts are set up correctly.")
	if len(result["sent"].([]any)) == 0 {
		return nil, httpapi.Fail(400, "Could not deliver the test message. Check the bot token and chat IDs.")
	}
	return body(map[string]any{"msg": "success", "sent": result["sent"], "failed": result["failed"]}), nil
}

// --- admin overview ---

func (h *h) adminOverview(ctx context.Context, _ *struct{}) (*anyBody, error) {
	app := h.app
	admin, err := app.User(ctx)
	if err != nil {
		return nil, err
	}
	if core.Str(admin, "role") != "admin" {
		return nil, httpapi.Fail(403, "Admin access required")
	}
	users, err := app.FindAll(ctx, "users", bson.M{}, options.Find().SetSort(core.Sort("created_at", 1)))
	if err != nil {
		return nil, err
	}
	machines, err := app.FindAll(ctx, "machines", bson.M{"deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return nil, err
	}
	connections, err := app.FindAll(ctx, "connections", bson.M{})
	if err != nil {
		return nil, err
	}
	byID := map[string]core.Doc{}
	byUser := map[string][]core.Doc{}
	for _, m := range machines {
		byID[core.IDString(m["_id"])] = m
		byUser[core.IDString(m["user_id"])] = append(byUser[core.IDString(m["user_id"])], m)
	}
	byMachine := map[string][]core.Doc{}
	for _, c := range connections {
		if !core.Truthy(c, "machine_id") {
			continue
		}
		key := core.IDString(c["machine_id"])
		byMachine[key] = append(byMachine[key], c)
	}
	port := func(c core.Doc) float64 {
		n, _ := core.Number(c["external_port"])
		return n
	}
	overview := []any{}
	for _, u := range users {
		uid := core.IDString(u["_id"])
		list := []any{}
		for _, m := range byUser[uid] {
			mid := core.IDString(m["_id"])
			conns := append([]core.Doc(nil), byMachine[mid]...)
			sort.SliceStable(conns, func(i, j int) bool { return port(conns[i]) < port(conns[j]) })
			ports := []any{}
			for _, c := range conns {
				ports = append(ports, app.SerializeConnection(c, byID[mid]))
			}
			entry := app.SerializeMachine(m)
			entry["num_ports"] = len(conns)
			entry["ports"] = ports
			list = append(list, entry)
		}
		email := u["email"]
		if !core.Truthy(u, "email") {
			email = core.Get(u, "username", "")
		}
		overview = append(overview, map[string]any{
			"user": map[string]any{"id": uid, "name": core.JSON(core.Get(u, "name", "")), "email": core.JSON(email),
				"role": core.JSON(core.Get(u, "role", "user")), "created_at": core.JSON(u["created_at"])},
			"machines": list,
		})
	}
	return body(map[string]any{"msg": "Platform overview loaded successfully", "data": overview}), nil
}
