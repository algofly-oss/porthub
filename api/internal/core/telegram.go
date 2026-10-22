package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// TelegramAPI is the Bot API base URL (tests point it elsewhere).
var TelegramAPI = "https://api.telegram.org"

var telegramClient = &http.Client{Timeout: 10 * time.Second}

func sendTelegram(ctx context.Context, botToken, chatID, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": text, "parse_mode": "HTML"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TelegramAPI+"/bot"+botToken+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := telegramClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("Telegram API returned %d: %s", resp.StatusCode, raw)
	}
	return nil
}

// SendTelegram mirrors send_telegram_message: {"sent": [...], "failed": [...]}.
func SendTelegram(ctx context.Context, botToken string, chatIDs []any, text string) map[string]any {
	botToken = strings.TrimSpace(botToken)
	sent, failed := []any{}, []any{}
	ids := []string{}
	for _, id := range chatIDs {
		if s := strings.TrimSpace(pyStr(id)); s != "" {
			ids = append(ids, s)
		}
	}
	if botToken == "" || len(ids) == 0 {
		return map[string]any{"sent": sent, "failed": failed}
	}
	for _, id := range ids {
		if err := sendTelegram(ctx, botToken, id, text); err != nil {
			log.Printf("Failed to send Telegram message to chat %s: %v", id, err)
			failed = append(failed, id)
		} else {
			sent = append(sent, id)
		}
	}
	return map[string]any{"sent": sent, "failed": failed}
}

// FormatLastSeen mirrors format_last_seen.
func FormatLastSeen(lastSeen any, now time.Time) string {
	t, ok := AsTime(lastSeen)
	if !ok {
		return "never"
	}
	s := int(now.Sub(t).Seconds())
	if s < 0 {
		s = 0
	}
	switch {
	case s < 60:
		return "just now"
	case s/60 < 60:
		return fmt.Sprintf("%dm ago", s/60)
	case s/3600 < 24:
		return fmt.Sprintf("%dh ago", s/3600)
	}
	return fmt.Sprintf("%dd ago", s/86400)
}

// TelegramConfig mirrors user_telegram_config.
type TelegramConfig struct {
	BotToken                                     string
	ChatIDs                                      []any
	AlertsEnabled, InstantEnabled, DigestEnabled bool
	DigestIntervalHours                          int
}

func UserTelegramConfig(user Doc) TelegramConfig {
	if user == nil {
		user = Doc{}
	}
	c := TelegramConfig{
		BotToken:       Str(user, "telegram_bot_token"),
		ChatIDs:        List(user, "telegram_chat_ids"),
		AlertsEnabled:  Truthy(user, "telegram_alerts_enabled"),
		InstantEnabled: truthy(Get(user, "telegram_instant_alerts_enabled", true)),
		DigestEnabled:  truthy(Get(user, "telegram_digest_enabled", true)),
	}
	if c.ChatIDs == nil {
		c.ChatIDs = []any{}
	}
	c.DigestIntervalHours = 6
	if n, ok := Number(user["telegram_digest_interval_hours"]); ok && n != 0 {
		c.DigestIntervalHours = int(n)
	}
	return c
}

func (a *App) sendInstantAlert(ctx context.Context, machine Doc, text string) {
	user, _ := a.FindOne(ctx, "users", bson.M{"_id": machine["user_id"]})
	c := UserTelegramConfig(user)
	if !c.AlertsEnabled || !c.InstantEnabled || c.BotToken == "" || len(c.ChatIDs) == 0 {
		return
	}
	SendTelegram(ctx, c.BotToken, c.ChatIDs, text)
}

func (a *App) alertAfter() time.Duration {
	return a.Cfg.MachineOnlineTTL + a.Cfg.MachineOfflineAlertGrace
}

// MarkOfflineMachinesAlerted mirrors mark_existing_offline_machines_alerted.
func (a *App) MarkOfflineMachinesAlerted(ctx context.Context) error {
	_, err := a.C("machines").UpdateMany(ctx,
		bson.M{"telegram_offline_alerted": bson.M{"$exists": false}, "last_seen_at": bson.M{"$lt": Now().Add(-a.alertAfter())}},
		bson.M{"$set": bson.M{"telegram_offline_alerted": true}})
	return err
}

func machineName(machine Doc) string {
	if n, ok := machine["name"].(string); ok && n != "" {
		return n
	}
	return "Machine"
}

// ProcessStatusAlert mirrors process_machine_status_alert.
func (a *App) ProcessStatusAlert(ctx context.Context, machine Doc, now time.Time) error {
	if IsFalse(machine, "enabled") || Truthy(machine, "telegram_alerts_excluded") {
		return nil
	}
	status := a.ConnectionStatus(machine)
	alerted := Truthy(machine, "telegram_offline_alerted")
	name := machineName(machine)
	if status == "offline" && !alerted {
		seen, ok := Time(machine, "last_seen_at")
		if !ok || now.Sub(seen) < a.alertAfter() {
			return nil
		}
		if _, err := a.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.M{"$set": bson.M{"telegram_offline_alerted": true}}); err != nil {
			return err
		}
		a.sendInstantAlert(ctx, machine, fmt.Sprintf("\U0001F534 <b>%s</b> went offline (last seen %s)", name, FormatLastSeen(seen, now)))
	} else if status != "offline" && alerted {
		if _, err := a.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.M{"$set": bson.M{"telegram_offline_alerted": false}}); err != nil {
			return err
		}
		a.sendInstantAlert(ctx, machine, fmt.Sprintf("\U0001F7E2 <b>%s</b> is back online", name))
	}
	return nil
}

// RunOfflineDigest mirrors monitor_offline_digest (every 10 minutes).
func (a *App) RunOfflineDigest(ctx context.Context) {
	for {
		a.offlineDigestOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

func (a *App) offlineDigestOnce(ctx context.Context) {
	now := Now()
	users, err := a.FindAll(ctx, "users", bson.M{"telegram_alerts_enabled": true, "telegram_digest_enabled": true,
		"telegram_bot_token": bson.M{"$exists": true, "$ne": ""}})
	if err != nil {
		log.Printf("Telegram digest: %v", err)
		return
	}
	for _, user := range users {
		if ctx.Err() != nil {
			return
		}
		c := UserTelegramConfig(user)
		if c.BotToken == "" || len(c.ChatIDs) == 0 {
			continue
		}
		if last, ok := Time(user, "telegram_last_batch_alert_at"); ok {
			hours := c.DigestIntervalHours
			if hours < 1 {
				hours = 1
			}
			if now.Sub(last) < time.Duration(hours)*time.Hour {
				continue
			}
		}
		machines, err := a.FindAll(ctx, "machines", bson.M{"user_id": user["_id"], "deletion_pending": bson.M{"$ne": true},
			"enabled": bson.M{"$ne": false}, "telegram_alerts_excluded": bson.M{"$ne": true}})
		if err != nil {
			log.Printf("Failed to send Telegram offline digest for user %v: %v", user["_id"], err)
			continue
		}
		lines := []string{"\U0001F4E1 <b>Machines still offline</b>"}
		for _, m := range machines {
			if a.ConnectionStatus(m) == "offline" && !Truthy(m, "telegram_alerts_excluded") {
				lines = append(lines, fmt.Sprintf("• %s — last seen %s", machineName(m), FormatLastSeen(m["last_seen_at"], now)))
			}
		}
		if len(lines) > 1 {
			SendTelegram(ctx, c.BotToken, c.ChatIDs, strings.Join(lines, "\n"))
		}
		_, _ = a.C("users").UpdateOne(ctx, bson.M{"_id": user["_id"]}, bson.M{"$set": bson.M{"telegram_last_batch_alert_at": now}})
	}
}
