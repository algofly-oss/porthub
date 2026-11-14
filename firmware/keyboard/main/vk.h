// Shared declarations of the Voice Keyboard firmware.
//
// The board is a client of the backend's /v1/keyboard socket (the same
// protocol as the desktop client) and types what it receives as a Bluetooth
// LE keyboard. The setup page in the browser configures it over USB serial.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

// Settings, kept in NVS. The setup page writes them; nothing is compiled in.
#define VK_SSID_MAX 32
#define VK_PASS_MAX 64
#define VK_SERVER_MAX 160
#define VK_TOKEN_MAX 160
#define VK_NAME_MAX 29   // what fits in a BLE scan response
#define VK_URLS_MAX 400

typedef struct {
    char ssid[VK_SSID_MAX + 1];
    char pass[VK_PASS_MAX + 1];
    char server[VK_SERVER_MAX + 1];  // https://host:port of the backend
    char token[VK_TOKEN_MAX + 1];    // install token until paired, then the device credential
    char name[VK_NAME_MAX + 1];      // Bluetooth name, also the name in Settings → Clients
    char *ca;                        // PEM of a private CA (Caddy's local CA), or NULL
    char urls[VK_URLS_MAX + 1];      // all addresses of the server, comma-separated (from "ready")
} vk_config_t;

extern vk_config_t vk_cfg;

void config_load(void);
bool config_save(void);
void config_erase(void);
bool config_complete(void);  // enough to connect: Wi-Fi, server and token

// Serial link to the setup page. Lines starting with '{' are commands;
// replies and events go out as "@vk {json}" so they stand out from logs.
typedef void (*io_line_handler_t)(char *line);
void io_init(io_line_handler_t handler);
void io_event(cJSON *event);  // sends and frees it

// Live state, pushed to the setup page as a "status" event on every change.
typedef struct {
    const char *wifi;    // off, connecting, connected, failed
    char wifi_error[48];
    char ip[16];
    int rssi;
    const char *server;  // off, connecting, connected, rejected, error
    char server_error[64];
    int device_id;
    bool selected;       // the account's active client: it types dictation
    const char *ble;     // advertising, connected, paired
    char ble_peer[18];
} vk_status_t;

vk_status_t *status_begin(void);  // locks the status for a change ...
void status_end(void);            // ... then unlocks and pushes it to the page
void status_emit(void);
bool status_ble_connected(void);
const char *status_ble_report(void);  // connected, waiting, off, pairing

// Wi-Fi and the backend connection.
void net_start(void);
void net_apply(bool wifi_changed, bool server_changed);  // after the settings change
cJSON *net_scan(void);                                   // array of {ssid, rssi, secure}
const char *vk_machine_id(void);
void net_ble_changed(void);  // tells the server whether a computer is connected over Bluetooth
void net_report_log(const char *line);  // a log line for the server (errors always, the rest for a live log)
bool net_log_streaming(void);           // the web app's live log is open
void net_activity(void);                // in use: full speed for a while (see net.c, power saving)

// Bluetooth LE keyboard.
void ble_start(void);
void ble_release_all(void);
void ble_set_name(const char *name);
void ble_forget(void);
void ble_set_enabled(bool on);
void ble_set_fast(bool on);  // the short connection interval (in use) or a longer one (idle)
void ble_pairing_mode(int seconds);  // drop the connection; refuse paired devices until a new one pairs  // off: disconnect and stop advertising, until on (or a restart)
bool ble_type(const char *text);             // queued; typed in order
bool ble_key(const char *key, const char *state);
// Touchpad: action "move" or "scroll" (dx, dy), or "click" (button left/right/middle).
bool ble_pointer(const char *action, int dx, int dy, const char *button);

// US layout: ASCII and the common typographic characters map to a key and
// modifiers; returns the number of keystrokes (0 when not typeable).
typedef struct {
    uint8_t mod;
    uint8_t code;
} vk_stroke_t;
int keymap_lookup(uint32_t codepoint, vk_stroke_t out[3]);
int keymap_named(const char *name);  // backspace, enter, up, ... → HID usage, or -1
