// Voice Keyboard for ESP32 boards: receives dictation from the backend over
// Wi-Fi and types it into a computer as a Bluetooth LE keyboard.
//
// Setup commands from the page (web/esp32.html), one JSON object per line:
//   {"cmd":"info"}      → {"ev":"info", chip, mac, version, name, ssid, server, configured, …}
//   {"cmd":"status"}    → {"ev":"status", wifi, server, ble, …} (also sent on every change)
//   {"cmd":"scan"}      → {"ev":"scan","networks":[{ssid, rssi, secure}]}
//   {"cmd":"config", "ssid", "pass", "server", "token", "name", "ca"}  (fields left out are kept)
//   {"cmd":"type","text":"…"}   types it over Bluetooth, without the server
//   {"cmd":"forget_bt"}         removes all paired computers
//   {"cmd":"erase"}             forgets everything and restarts
//   {"cmd":"reboot"}
// Each command gets {"ev":"ok","cmd":…} or {"ev":"error","cmd":…,"msg":…}.
// The Wi-Fi password and the token are never sent back.
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "vk.h"

static const char *TAG = "vkeyboard";

// ---- Status ----

static vk_status_t status = {.wifi = "off", .server = "off", .ble = "starting"};
static SemaphoreHandle_t status_lock;

vk_status_t *status_begin(void)
{
    xSemaphoreTake(status_lock, portMAX_DELAY);
    return &status;
}

static cJSON *status_json_locked(void)
{
    cJSON *s = cJSON_CreateObject();
    cJSON_AddStringToObject(s, "ev", "status");
    cJSON_AddStringToObject(s, "wifi", status.wifi);
    cJSON_AddStringToObject(s, "wifi_error", status.wifi_error);
    cJSON_AddStringToObject(s, "ip", status.ip);
    cJSON_AddNumberToObject(s, "rssi", status.rssi);
    cJSON_AddStringToObject(s, "server", status.server);
    cJSON_AddStringToObject(s, "server_error", status.server_error);
    cJSON_AddNumberToObject(s, "device", status.device_id);
    cJSON_AddBoolToObject(s, "selected", status.selected);
    cJSON_AddStringToObject(s, "ble", status.ble);
    cJSON_AddStringToObject(s, "ble_peer", status.ble_peer);
    cJSON_AddNumberToObject(s, "heap", esp_get_free_heap_size());
    return s;
}

void status_end(void)
{
    static int reported = -1;  // Bluetooth as last told to the server: 0 waiting, 1 connected, 2 off
    cJSON *s = status_json_locked();
    int ble = strcmp(status.ble, "connected") == 0 ? 1 : strcmp(status.ble, "off") == 0 ? 2
            : strcmp(status.ble, "pairing") == 0 ? 3 : 0;
    bool changed = ble != reported;
    reported = ble;
    xSemaphoreGive(status_lock);
    io_event(s);
    if (changed) {
        net_ble_changed();
    }
}

const char *status_ble_report(void)  // for the server: connected, waiting, off, pairing
{
    xSemaphoreTake(status_lock, portMAX_DELAY);
    const char *r = strcmp(status.ble, "connected") == 0 ? "connected" : strcmp(status.ble, "off") == 0 ? "off"
                  : strcmp(status.ble, "pairing") == 0 ? "pairing" : "waiting";
    xSemaphoreGive(status_lock);
    return r;
}

bool status_ble_connected(void)
{
    xSemaphoreTake(status_lock, portMAX_DELAY);
    bool connected = strcmp(status.ble, "connected") == 0;
    xSemaphoreGive(status_lock);
    return connected;
}

void status_emit(void)
{
    status_begin();
    status_end();
}

// ---- Commands ----

static void reply_ok(const char *cmd)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "ev", "ok");
    cJSON_AddStringToObject(r, "cmd", cmd);
    io_event(r);
}

static void reply_error(const char *cmd, const char *msg)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "ev", "error");
    cJSON_AddStringToObject(r, "cmd", cmd ? cmd : "");
    cJSON_AddStringToObject(r, "msg", msg);
    io_event(r);
}

static void send_info(void)
{
    uint8_t mac[6];
    char mac_text[18];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(mac_text, sizeof mac_text, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    uint32_t flash = 0;
    esp_flash_get_size(NULL, &flash);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "ev", "info");
    cJSON_AddStringToObject(r, "fw", "vkeyboard");
    cJSON_AddStringToObject(r, "version", esp_app_get_description()->version);
    cJSON_AddStringToObject(r, "chip", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(r, "revision", chip.revision);
    cJSON_AddNumberToObject(r, "flash", flash);
    cJSON_AddStringToObject(r, "mac", mac_text);
    cJSON_AddStringToObject(r, "machine", vk_machine_id());
    cJSON_AddStringToObject(r, "name", vk_cfg.name);
    cJSON_AddStringToObject(r, "ssid", vk_cfg.ssid);
    cJSON_AddStringToObject(r, "server", vk_cfg.server);
    cJSON_AddBoolToObject(r, "has_pass", vk_cfg.pass[0] != '\0');
    cJSON_AddBoolToObject(r, "has_token", vk_cfg.token[0] != '\0');
    cJSON_AddBoolToObject(r, "has_ca", vk_cfg.ca != NULL);
    cJSON_AddBoolToObject(r, "configured", config_complete());
    io_event(r);
}

// Copies a string field if present; false if it is too long.
static bool take(cJSON *m, const char *key, char *out, size_t size, bool *changed)
{
    cJSON *v = cJSON_GetObjectItem(m, key);
    if (!cJSON_IsString(v)) {
        return true;
    }
    if (strlen(v->valuestring) >= size) {
        return false;
    }
    if (strcmp(out, v->valuestring) != 0) {
        strlcpy(out, v->valuestring, size);
        *changed = true;
    }
    return true;
}

static void configure(cJSON *m)
{
    vk_config_t old = vk_cfg;
    bool wifi = false, server = false, name = false;
    if (!take(m, "ssid", vk_cfg.ssid, sizeof vk_cfg.ssid, &wifi) ||
        !take(m, "pass", vk_cfg.pass, sizeof vk_cfg.pass, &wifi) ||
        !take(m, "server", vk_cfg.server, sizeof vk_cfg.server, &server) ||
        !take(m, "token", vk_cfg.token, sizeof vk_cfg.token, &server) ||
        !take(m, "name", vk_cfg.name, sizeof vk_cfg.name, &name)) {
        vk_cfg = old;
        reply_error("config", "a value is too long");
        return;
    }
    if (vk_cfg.server[0] && strncmp(vk_cfg.server, "https://", 8) && strncmp(vk_cfg.server, "http://", 7)) {
        vk_cfg = old;
        reply_error("config", "the server address must start with https:// or http://");
        return;
    }
    if (strcmp(old.server, vk_cfg.server) != 0) {
        vk_cfg.urls[0] = '\0';  // the addresses of the old server; the new one sends its own
    }
    cJSON *ca = cJSON_GetObjectItem(m, "ca");
    if (cJSON_IsString(ca) || cJSON_IsNull(ca)) {
        const char *pem = cJSON_IsString(ca) && ca->valuestring[0] ? ca->valuestring : NULL;
        if (!pem != !vk_cfg.ca || (pem && strcmp(pem, vk_cfg.ca) != 0)) {
            vk_cfg.ca = pem ? strdup(pem) : NULL;  // the old copy stays valid for a running connection
            server = true;
        }
    }
    if (!config_save()) {
        reply_error("config", "could not save the settings");
        return;
    }
    if (name) {
        ble_set_name(vk_cfg.name);
        server = true;  // the new name shows in Settings → Clients after the next hello
    }
    net_apply(wifi, server);
    reply_ok("config");
    send_info();
}

static volatile bool started;  // commands wait until Wi-Fi and Bluetooth are up; the page retries

static void on_command(char *line)
{
    if (!started) {
        return;
    }
    cJSON *m = cJSON_Parse(line);
    const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(m, "cmd"));
    if (!cmd) {
        reply_error(NULL, "not a command");
    } else if (strcmp(cmd, "info") == 0) {
        send_info();
    } else if (strcmp(cmd, "status") == 0) {
        status_emit();
    } else if (strcmp(cmd, "scan") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "ev", "scan");
        cJSON_AddItemToObject(r, "networks", net_scan());
        io_event(r);
    } else if (strcmp(cmd, "config") == 0) {
        configure(m);
    } else if (strcmp(cmd, "type") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(m, "text"));
        ble_type(text ? text : "Hello from Voice Keyboard");
        reply_ok(cmd);
    } else if (strcmp(cmd, "forget_bt") == 0) {
        ble_forget();
        reply_ok(cmd);
    } else if (strcmp(cmd, "erase") == 0) {
        config_erase();
        ble_forget();
        reply_ok(cmd);
        vTaskDelay(pdMS_TO_TICKS(300));
        esp_restart();
    } else if (strcmp(cmd, "reboot") == 0) {
        reply_ok(cmd);
        vTaskDelay(pdMS_TO_TICKS(300));
        esp_restart();
    } else {
        reply_error(cmd, "unknown command");
    }
    cJSON_Delete(m);
}

// Why the board started, as a warning, so the server's client log shows
// crashes and power problems (sent once Wi-Fi and the server are up).
static void log_reset_reason(void)
{
    const char *why;
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON: why = "power on (plugged in, or the reset button)"; break;
    case ESP_RST_EXT: why = "the reset pin"; break;
    case ESP_RST_SW: why = "a restart it was asked for"; break;
    case ESP_RST_PANIC: why = "a crash (firmware bug)"; break;
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT: why = "a watchdog: the firmware hung"; break;
    case ESP_RST_BROWNOUT: why = "a power dip (weak USB power or cable)"; break;
    case ESP_RST_DEEPSLEEP: why = "waking from deep sleep"; break;
    default: why = "an unknown reason"; break;
    }
    ESP_LOGW(TAG, "started after %s", why);
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    status_lock = xSemaphoreCreateMutex();
    config_load();
    if (!vk_cfg.name[0]) {
        // Distinct by default, so several boards can be told apart when pairing.
        snprintf(vk_cfg.name, sizeof vk_cfg.name, "Voice Keyboard %s", vk_machine_id() + 14);
    }
    io_init(on_command);  // first: Wi-Fi and Bluetooth report their status through it
    ESP_LOGI(TAG, "Voice Keyboard %s on %s", esp_app_get_description()->version, CONFIG_IDF_TARGET);
    log_reset_reason();
    ble_start();
    net_start();
    started = true;
    send_info();
    status_emit();
}
