// Wi-Fi and the connection to the backend's /api/keyboard/device/{id} socket.
//
// Protocol (the desktop client's, see desktop/client.go):
//   client -> {"type":"hello","client":"<name>","machine":"…","platform":"…","version":"…"}
//   server -> {"type":"ready","device":7,"credential":"…","selected":true,"urls":[…],"ca":"…"}
//   server -> {"type":"selected","selected":false}
//   server -> {"type":"segment","text":"…"} / {"type":"key","key":"enter","state":"press"}
//   server -> {"type":"wake"}  the web app opened or was touched: full speed (power saving)
// The first connection uses the account's install token; the credential in
// "ready" replaces it, so a new install token later does not unpair the board.
//
// Addresses: "ready" lists every address of the server (VK_URLS), e.g. its LAN
// address and a Cloudflare name, and its local CA. A connection goes to the
// first local address that accepts a TCP connection, else to a public one;
// while on a public address, local ones are re-checked on every heartbeat
// tick (~12 s), so back home the board moves to the LAN within seconds. The
// credential being accepted shows it is the same deployment (another server
// rejects it, and the board then goes back to the address it was set up with).
//
// One task (net_task) starts and stops the socket; the socket's own event
// handler only reports to it, as the client cannot be stopped from there.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_websocket_client.h"
#include "esp_wifi.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"
#include "vk.h"

static const char *TAG = "net";

#define MESSAGE_MAX (32 * 1024)  // a long dictation arrives as one segment
#define CLOSE_BAD_CREDENTIAL 4401
#define REJECTED_RETRY_MS (60 * 1000)
// Roaming: with a weak signal, move to an access point of the same network
// that is clearly stronger (mesh systems and extenders share one name).
// Heartbeat: a proxy in between (Cloudflare) can keep our side of a dead
// connection open after the server restarts; no pong in time, reconnect.
#define PING_EVERY_MS (25 * 1000)
#define PONG_WITHIN_MS (15 * 1000)
#define ROAM_CHECK_MS (30 * 1000)
#define ROAM_WEAK_RSSI (-67)
#define ROAM_MARGIN_DB 8
#define LOCAL_BACKOFF_MS (60 * 1000)         // after a local address failed (a server restart fails every address)
#define FAILOVER_AFTER 3                     // failed attempts before trying another address
#define MAX_ADDRESSES 6
// Power saving: left alone this long, Wi-Fi sleeps between the router's beacons
// and Bluetooth slows down, so the board runs cooler. Typing, the touchpad, or
// the web app opening (it sends "wake") bring full speed back at once.
#define IDLE_AFTER_MS (5 * 60 * 1000)

typedef enum {
    EV_WIFI_UP,
    EV_WIFI_DOWN,
    EV_APPLY_WIFI,
    EV_APPLY_SERVER,
    EV_CREDENTIAL,   // the server issued a credential; reconnect with it
    EV_REJECTED,     // install token or credential no longer valid
    EV_TLS_FAILED,
    EV_ROAM_CHECK,
    EV_BLE,          // Bluetooth connected or lost: tell the server
    EV_PING,         // heartbeat timer
    EV_LOG,          // lines for an open live log
    EV_FAILED,       // a connection attempt failed
    EV_WAKE,         // input after a quiet spell: full speed
} net_event_t;

static QueueHandle_t events;
static esp_websocket_client_handle_t ws;
static char *ws_uri, *ws_headers;
static esp_timer_handle_t reconnect_timer, roam_timer, ping_timer;
static int64_t ping_sent_us;  // an unanswered ping, or 0
static volatile bool wifi_up, scanning;
static int wifi_failures;
static bool ca_flipped;  // the CA choice for this address failed; try the other one
static char active[VK_SERVER_MAX + 1];  // the address in use, "" to choose again
static int failures;                     // failed attempts on it in a row
static int64_t local_failed_us;          // when a local address last failed
static char machine[32];
static char input_session[40];
static volatile bool ready;  // the server accepted us ("ready"); status messages may go out
static volatile int64_t last_activity_us;
static volatile bool full_speed;  // set at start, then by net_task only

// Received message being reassembled from frames.
static char *message;
static size_t message_len;

static void ws_start(void);

static void post(net_event_t ev)
{
    if (events) {  // Bluetooth starts before the network
        xQueueSend(events, &ev, 0);
    }
}

void net_ble_changed(void)
{
    post(EV_BLE);
}

static const char *chip_name(void);

// Error and warning lines for the server (GET /api/client-errors). The log
// hook only copies them here; net_task sends them, so sending cannot recurse.
#define LOG_SLOTS 24
#define LOG_LINE_MAX 200
static char log_ring[LOG_SLOTS][LOG_LINE_MAX];
static int log_head, log_count;
static volatile int64_t log_stream_until_us;  // the web app's live log is open
static volatile bool log_send_pending;

bool net_log_streaming(void)
{
    return log_stream_until_us && esp_timer_get_time() < log_stream_until_us;
}
static portMUX_TYPE log_lock = portMUX_INITIALIZER_UNLOCKED;

void net_report_log(const char *line)
{
    char clean[LOG_LINE_MAX];
    size_t n = 0;
    for (const char *p = line; *p && n < sizeof clean - 1; p++) {
        if (*p == '\x1b') {  // drop colour codes
            while (*p && *p != 'm') p++;
            if (!*p) break;
            continue;
        }
        if (*p != '\n' && *p != '\r') clean[n++] = *p;
    }
    clean[n] = '\0';
    taskENTER_CRITICAL(&log_lock);
    int last = (log_head + log_count - 1 + LOG_SLOTS) % LOG_SLOTS;
    // The same message again (a retry loop): skip it; the timestamp differs, so compare after it.
    const char *a = strchr(clean, ')'), *b = log_count ? strchr(log_ring[last], ')') : NULL;
    if (!(a && b && strcmp(a, b) == 0)) {
        if (log_count == LOG_SLOTS) {  // full: drop the oldest
            log_head = (log_head + 1) % LOG_SLOTS;
            log_count--;
        }
        strlcpy(log_ring[(log_head + log_count) % LOG_SLOTS], clean, LOG_LINE_MAX);
        log_count++;
    }
    taskEXIT_CRITICAL(&log_lock);
    if (net_log_streaming() && !log_send_pending) {  // live: send now, not at the next heartbeat
        log_send_pending = true;
        post(EV_LOG);
    }
}

static void send_log_reports(void)
{
    while (ws && ready && esp_websocket_client_is_connected(ws)) {
        char line[LOG_LINE_MAX];
        taskENTER_CRITICAL(&log_lock);
        bool any = log_count > 0;
        if (any) {
            memcpy(line, log_ring[log_head], sizeof line);
            log_head = (log_head + 1) % LOG_SLOTS;
            log_count--;
        }
        taskEXIT_CRITICAL(&log_lock);
        if (!any) {
            return;
        }
        char message[LOG_LINE_MAX + 48];
        snprintf(message, sizeof message, "%s %s: %s", esp_app_get_description()->version, chip_name(), line);
        cJSON *m = cJSON_CreateObject();
        cJSON_AddStringToObject(m, "type", "log");
        // Errors and warnings are kept by the server; other lines only go to an open live log.
        cJSON_AddStringToObject(m, "level", line[0] == 'E' || line[0] == 'W' ? "error" : "info");
        cJSON_AddStringToObject(m, "message", message);
        char *text = cJSON_PrintUnformatted(m);
        cJSON_Delete(m);
        if (text) {
            esp_websocket_client_send_text(ws, text, strlen(text), pdMS_TO_TICKS(2000));
            free(text);
        }
    }
}

static void send_ble_status(void)
{
    if (!ws || !ready || !esp_websocket_client_is_connected(ws)) {
        return;
    }
    char text[192];
    int n = snprintf(text, sizeof text, "{\"type\":\"device_status\",\"session\":\"%s\",\"bluetooth\":\"%s\"}",
                     input_session,status_ble_report());
    esp_websocket_client_send_text(ws, text, n, pdMS_TO_TICKS(2000));
}

const char *vk_machine_id(void)
{
    if (!machine[0]) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(machine, sizeof machine, "esp32-%02x%02x%02x%02x%02x%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    return machine;
}

static const char *chip_name(void)
{
#if CONFIG_IDF_TARGET_ESP32C3
    return "ESP32-C3";
#else
    return "ESP32";
#endif
}

// ---- Wi-Fi ----

static const char *wifi_reason(uint8_t reason)
{
    switch (reason) {
    case WIFI_REASON_NO_AP_FOUND:
        return "network not found";
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_MIC_FAILURE:
        return "wrong password";
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
        return "network security not supported";
    case WIFI_REASON_ASSOC_LEAVE:
        return "";
    default:
        return NULL;
    }
}

static void wifi_connect(void)
{
    if (!vk_cfg.ssid[0] || scanning) {
        return;
    }
    wifi_config_t wc = {0};
    strlcpy((char *)wc.sta.ssid, vk_cfg.ssid, sizeof wc.sta.ssid);
    strlcpy((char *)wc.sta.password, vk_cfg.pass, sizeof wc.sta.password);
    wc.sta.threshold.authmode = WIFI_AUTH_OPEN;  // open networks too
    wc.sta.pmf_cfg.capable = true;
    wc.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wc.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    vk_status_t *s = status_begin();
    if (strcmp(s->wifi, "failed") != 0) {
        s->wifi = "connecting";
    }
    status_end();
    esp_wifi_connect();
}

static void reconnect_cb(void *arg)
{
    wifi_connect();
}

static void roam_cb(void *arg)
{
    post(EV_ROAM_CHECK);
}

static void ping_cb(void *arg)
{
    post(EV_PING);
}

// Called from net_task. wifi_connect() always joins the strongest access point
// (all-channel scan, sorted by signal), so moving is a disconnect and rejoin.
static void roam_check(void)
{
    wifi_ap_record_t cur;
    if (!wifi_up || scanning || esp_wifi_sta_get_ap_info(&cur) != ESP_OK) {
        return;
    }
    vk_status_t *s = status_begin();
    s->rssi = cur.rssi;
    status_end();  // keeps the page's signal reading current
    if (cur.rssi >= ROAM_WEAK_RSSI) {
        return;
    }
    wifi_scan_config_t sc = {.ssid = (uint8_t *)vk_cfg.ssid};
    uint16_t n = 0;
    wifi_ap_record_t *aps = NULL;
    scanning = true;
    if (esp_wifi_scan_start(&sc, true) == ESP_OK && esp_wifi_scan_get_ap_num(&n) == ESP_OK && n) {
        aps = calloc(n, sizeof *aps);
        if (!aps || esp_wifi_scan_get_ap_records(&n, aps) != ESP_OK) {
            n = 0;
        }
    } else {
        esp_wifi_clear_ap_list();
    }
    scanning = false;
    const wifi_ap_record_t *best = NULL;
    for (int i = 0; i < n; i++) {
        if (memcmp(aps[i].bssid, cur.bssid, 6) != 0 && (!best || aps[i].rssi > best->rssi)) {
            best = &aps[i];
        }
    }
    if (best && best->rssi >= cur.rssi + ROAM_MARGIN_DB) {
        ESP_LOGI(TAG, "roaming: %d dBm here, %d dBm at " MACSTR " (channel %d)", cur.rssi, best->rssi,
                 MAC2STR(best->bssid), best->primary);
        esp_wifi_disconnect();  // on_wifi reconnects, to the strongest
    }
    free(aps);
}

static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = data;
        bool was_up = wifi_up;
        wifi_up = false;
        if (was_up) {
            post(EV_WIFI_DOWN);
        }
        const char *why = wifi_reason(d->reason);
        if ((d->reason == WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY ||
             d->reason == WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD) && !vk_cfg.pass[0]) {
            why = "this network needs a password";
        }
        vk_status_t *s = status_begin();
        s->ip[0] = '\0';
        if (vk_cfg.ssid[0]) {
            if (why && !*why) {
                s->wifi_error[0] = '\0';  // we disconnected on purpose
            } else if (why) {
                strlcpy(s->wifi_error, why, sizeof s->wifi_error);
            } else {
                snprintf(s->wifi_error, sizeof s->wifi_error, "disconnected (reason %d)", d->reason);
            }
            s->wifi = ++wifi_failures >= 3 && s->wifi_error[0] ? "failed" : "connecting";
        } else {
            s->wifi = "off";
        }
        status_end();
        if (vk_cfg.ssid[0] && !scanning) {
            esp_timer_stop(reconnect_timer);
            esp_timer_start_once(reconnect_timer, (wifi_failures < 5 ? 2000 : 10000) * 1000LL);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        wifi_ap_record_t ap;
        wifi_up = true;
        wifi_failures = 0;
        vk_status_t *s = status_begin();
        s->wifi = "connected";
        s->wifi_error[0] = '\0';
        snprintf(s->ip, sizeof s->ip, IPSTR, IP2STR(&e->ip_info.ip));
        s->rssi = esp_wifi_sta_get_ap_info(&ap) == ESP_OK ? ap.rssi : 0;
        status_end();
        ESP_LOGI(TAG, "Wi-Fi connected, IP %s", s->ip);
        post(EV_WIFI_UP);
    }
}

cJSON *net_scan(void)
{
    cJSON *list = cJSON_CreateArray();
    // A scan fails while the station is trying to connect, so pause that.
    scanning = true;
    if (!wifi_up) {
        esp_timer_stop(reconnect_timer);
        esp_wifi_disconnect();
    }
    wifi_scan_config_t sc = {0};
    esp_err_t err = esp_wifi_scan_start(&sc, true);
    uint16_t n = 0;
    wifi_ap_record_t *aps = NULL;
    if (err == ESP_OK && esp_wifi_scan_get_ap_num(&n) == ESP_OK && n) {
        n = n > 30 ? 30 : n;
        aps = calloc(n, sizeof *aps);
        if (!aps || esp_wifi_scan_get_ap_records(&n, aps) != ESP_OK) {
            n = 0;
        }
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan failed: %s", esp_err_to_name(err));
    }
    // Strongest first; one entry per network name.
    for (int i = 0; i < n; i++) {
        const char *ssid = (const char *)aps[i].ssid;
        bool seen = !ssid[0];
        for (int j = 0; j < i && !seen; j++) {
            seen = strcmp(ssid, (const char *)aps[j].ssid) == 0;
        }
        if (seen) {
            continue;
        }
        cJSON *ap = cJSON_CreateObject();
        cJSON_AddStringToObject(ap, "ssid", ssid);
        cJSON_AddNumberToObject(ap, "rssi", aps[i].rssi);
        cJSON_AddBoolToObject(ap, "secure", aps[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(list, ap);
    }
    free(aps);
    scanning = false;
    if (!wifi_up) {
        wifi_connect();
    }
    return list;
}

// ---- Backend socket ----

static void send_hello(void)
{
    cJSON *hello = cJSON_CreateObject();
    cJSON_AddStringToObject(hello, "type", "hello");
    cJSON_AddStringToObject(hello, "client", vk_cfg.name);
    cJSON_AddStringToObject(hello, "machine", vk_machine_id());
    cJSON_AddStringToObject(hello, "platform", chip_name());
    cJSON_AddStringToObject(hello, "version", esp_app_get_description()->version);
    char *text = cJSON_PrintUnformatted(hello);
    cJSON_Delete(hello);
    esp_websocket_client_send_text(ws, text, strlen(text), pdMS_TO_TICKS(5000));
    free(text);
}

// --- Addresses of the server ---

// host and port of http(s)://host[:port][/…]
static bool url_host(const char *url, char *host, size_t size, char *port, size_t port_size)
{
    bool secure = strncmp(url, "https://", 8) == 0;
    const char *h = strstr(url, "://");
    if (!h) {
        return false;
    }
    h += 3;
    size_t len = strcspn(h, ":/");
    if (!len || len >= size) {
        return false;
    }
    memcpy(host, h, len);
    host[len] = '\0';
    if (h[len] == ':') {
        size_t plen = strcspn(h + len + 1, "/");
        if (!plen || plen >= port_size) {
            return false;
        }
        memcpy(port, h + len + 1, plen);
        port[plen] = '\0';
    } else {
        strlcpy(port, secure ? "443" : "80", port_size);
    }
    return true;
}

// A private IP, a .local name or a single-label name.
static bool is_local(const char *url)
{
    char host[VK_SERVER_MAX + 1], port[8];
    if (!url_host(url, host, sizeof host, port, sizeof port)) {
        return false;
    }
    unsigned a, b, c, d;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) ||
               (a == 169 && b == 254);
    }
    size_t n = strlen(host);
    return strcmp(host, "localhost") == 0 || !strchr(host, '.') || (n > 6 && strcmp(host + n - 6, ".local") == 0);
}

// Whether the address accepts a TCP connection within 1.5 s (no TLS: cheap on memory).
static bool reachable(const char *url)
{
    char host[VK_SERVER_MAX + 1], port[8];
    if (!url_host(url, host, sizeof host, port, sizeof port)) {
        return false;
    }
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *ai = NULL;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || !ai) {
        return false;
    }
    bool ok = false;
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd >= 0) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            ok = true;
        } else if (errno == EINPROGRESS) {
            fd_set w;
            FD_ZERO(&w);
            FD_SET(fd, &w);
            struct timeval tv = {.tv_sec = 1, .tv_usec = 500000};
            int err = 0;
            socklen_t len = sizeof err;
            ok = select(fd + 1, NULL, &w, NULL, &tv) == 1 &&
                 getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
        }
        close(fd);
    }
    freeaddrinfo(ai);
    return ok;
}

// The address the board was set up with, then the ones the server listed.
static int addresses(char out[][VK_SERVER_MAX + 1])
{
    int n = 0;
    strlcpy(out[n++], vk_cfg.server, VK_SERVER_MAX + 1);
    const char *p = vk_cfg.urls;
    while (*p && n < MAX_ADDRESSES) {
        size_t len = strcspn(p, ",");
        if (len && len <= VK_SERVER_MAX) {
            memcpy(out[n], p, len);
            out[n][len] = '\0';
            bool seen = false;
            for (int i = 0; i < n; i++) {
                seen = seen || strcmp(out[i], out[n]) == 0;
            }
            if (!seen) {
                n++;
            }
        }
        p += len;
        if (*p == ',') {
            p++;
        }
    }
    return n;
}

static bool local_allowed(void)
{
    return !local_failed_us || esp_timer_get_time() - local_failed_us > LOCAL_BACKOFF_MS * 1000LL;
}

// Chooses the address to connect to: a reachable local one, else a public
// one (the one after `after`, when that failed), else the configured one.
static void choose_address(const char *after)
{
    static char list[MAX_ADDRESSES][VK_SERVER_MAX + 1];
    int n = addresses(list);
    char previous[VK_SERVER_MAX + 1];
    strlcpy(previous, after ? after : "", sizeof previous);
    ca_flipped = false;
    failures = 0;
    if (local_allowed()) {
        for (int i = 0; i < n; i++) {
            if (is_local(list[i]) && strcmp(list[i], previous) != 0 && reachable(list[i])) {
                strlcpy(active, list[i], sizeof active);
                return;
            }
        }
    }
    int start = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i], previous) == 0) {
            start = i + 1;
        }
    }
    for (int k = 0; k < n; k++) {
        const char *u = list[(start + k) % n];
        if (!is_local(u) && strcmp(u, previous) != 0) {
            strlcpy(active, u, sizeof active);
            return;
        }
    }
    strlcpy(active, vk_cfg.server, sizeof active);
}

// On a public address: connects to a local one that accepts a connection.
static bool switch_to_local(void)
{
    static char list[MAX_ADDRESSES][VK_SERVER_MAX + 1];
    int n = addresses(list);
    for (int i = 0; i < n; i++) {
        if (is_local(list[i]) && reachable(list[i])) {
            ESP_LOGI(TAG, "%s is reachable; switching to it", list[i]);
            strlcpy(active, list[i], sizeof active);
            ca_flipped = false;
            failures = 0;
            ws_start();
            return true;
        }
    }
    return false;
}

// Keeps the addresses and local CA that "ready" sends.
static void learn_addresses(cJSON *m) { (void)m; /* PortHub owns route discovery; never replace the endpoint. */ }

void net_activity(void)
{
    last_activity_us = esp_timer_get_time();
    if (!full_speed) {
        post(EV_WAKE);
    }
}

static void set_full_speed(bool on)
{
    full_speed = on;
    // Asleep, the radio wakes only for the router's beacons (~100 ms), so
    // touchpad motion would arrive in bursts and the pointer jump.
    esp_err_t ps = esp_wifi_set_ps(on ? WIFI_PS_NONE : WIFI_PS_MIN_MODEM);
    if (ps != ESP_OK) {
        ESP_LOGW(TAG, "Wi-Fi power saving not changed: %s", esp_err_to_name(ps));
    }
    ble_set_fast(on);
    ESP_LOGI(TAG, "%s", on ? "in use: full speed" : "idle: power saving");
}

static char last_input_id[40];
static bool last_input_ok;
static void input_ack(const char *id, bool ok, const char *error)
{
    cJSON *m=cJSON_CreateObject(), *ack=cJSON_CreateObject();
    cJSON_AddStringToObject(m,"type","ack");
    cJSON_AddStringToObject(m,"session",input_session);
    cJSON_AddStringToObject(ack,"id",id);
    cJSON_AddBoolToObject(ack,"ok",ok);
    if (error) cJSON_AddStringToObject(ack,"error",error);
    cJSON_AddItemToObject(m,"ack",ack);
    char *wire=cJSON_PrintUnformatted(m);
    if (wire && ws) esp_websocket_client_send_text(ws,wire,strlen(wire),pdMS_TO_TICKS(200));
    free(wire);cJSON_Delete(m);
}
static void handle_message(const char *text)
{
    cJSON *m = cJSON_Parse(text);
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(m, "type"));
    if (!type) {
        cJSON_Delete(m);
        return;
    }
    const char *session=cJSON_GetStringValue(cJSON_GetObjectItem(m,"session"));
    if (strcmp(type,"start")==0 && session && strlen(session)<sizeof input_session) {
        ble_release_all();strlcpy(input_session,session,sizeof input_session);last_input_id[0]='\0';send_ble_status();
        cJSON_Delete(m);return;
    }
    if (strcmp(type,"stop")==0 && session && strcmp(session,input_session)==0) {
        ble_release_all();input_session[0]='\0';cJSON_Delete(m);return;
    }
    if (strcmp(type,"input")==0) {
        cJSON *input=cJSON_GetObjectItem(m,"input"), *cmd=cJSON_GetObjectItem(input,"command");
        const char *request=cJSON_GetStringValue(cJSON_GetObjectItem(input,"id"));
        const char *kind=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"type"));
        if (!session || strcmp(session,input_session)!=0 || !request || strlen(request)!=36 || !kind) {cJSON_Delete(m);return;}
        if (strcmp(request,last_input_id)==0) {input_ack(request,last_input_ok,last_input_ok?NULL:"Input was not queued");cJSON_Delete(m);return;}
        bool ok=false;net_activity();
        if (strcmp(kind,"text")==0) {const char *value=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"text"));ok=value && strlen(value)<=8192 && ble_type(value);}
        else if (strcmp(kind,"key")==0) {const char *key=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"key")), *state=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"state"));ok=key && ble_key(key,state?state:"press");}
        else if (strcmp(kind,"pointer")==0) {const char *action=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"action")), *button=cJSON_GetStringValue(cJSON_GetObjectItem(cmd,"button"));ok=action && ble_pointer(action,(int)cJSON_GetNumberValue(cJSON_GetObjectItem(cmd,"dx")),(int)cJSON_GetNumberValue(cJSON_GetObjectItem(cmd,"dy")),button?button:"left");}
        else if (strcmp(kind,"release_all")==0) {ble_release_all();ok=true;}
        strlcpy(last_input_id,request,sizeof last_input_id);last_input_ok=ok;
        input_ack(request,ok,ok?NULL:"Bluetooth input unavailable, unsupported text, or queue full");cJSON_Delete(m);return;
    }
    if (strcmp(type,"device")==0) {
        if (session && strcmp(session,input_session)==0) {char *command=cJSON_PrintUnformatted(cJSON_GetObjectItem(m,"command"));if(command){handle_message(command);free(command);}}
        cJSON_Delete(m);return;
    }
    if (strcmp(type, "segment") == 0 || strcmp(type, "key") == 0 || strcmp(type, "pointer") == 0 ||
        strcmp(type, "wake") == 0 || (strcmp(type, "selected") == 0 && cJSON_IsTrue(cJSON_GetObjectItem(m, "selected")))) {
        net_activity();
    }
    if (strcmp(type, "segment") == 0) {
        const char *t = cJSON_GetStringValue(cJSON_GetObjectItem(m, "text"));
        if (t) {
            ble_type(t);
        }
    } else if (strcmp(type, "key") == 0) {
        const char *key = cJSON_GetStringValue(cJSON_GetObjectItem(m, "key"));
        const char *state = cJSON_GetStringValue(cJSON_GetObjectItem(m, "state"));
        if (key) {
            ble_key(key, state ? state : "press");
        }
    } else if (strcmp(type, "forget") == 0) {  // forget every paired device (they must pair again)
        ESP_LOGI(TAG, "forgetting all paired devices");
        ble_forget();
    } else if (strcmp(type, "pairing") == 0) {
        int seconds = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(m, "seconds"));
        ble_pairing_mode(seconds >= 10 && seconds <= 600 ? seconds : 120);
    } else if (strcmp(type, "logs") == 0) {
        log_stream_until_us = cJSON_IsTrue(cJSON_GetObjectItem(m, "on")) ? esp_timer_get_time() + 600 * 1000000LL : 0;
        ESP_LOGI(TAG, "live log %s", log_stream_until_us ? "on (10 min at most)" : "off");
    } else if (strcmp(type, "bluetooth") == 0) {
        ble_set_enabled(cJSON_IsTrue(cJSON_GetObjectItem(m, "on")));
    } else if (strcmp(type, "pointer") == 0) {
        const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(m, "action"));
        if (action) {
            ble_pointer(action, (int)cJSON_GetNumberValue(cJSON_GetObjectItem(m, "dx")),
                        (int)cJSON_GetNumberValue(cJSON_GetObjectItem(m, "dy")),
                        cJSON_GetStringValue(cJSON_GetObjectItem(m, "button")));
        }
    } else if (strcmp(type, "pong") == 0) {
        ping_sent_us = 0;
    } else if (strcmp(type, "ready") == 0 || strcmp(type, "selected") == 0) {
        vk_status_t *s = status_begin();
        s->selected = cJSON_IsTrue(cJSON_GetObjectItem(m, "selected"));
        if (strcmp(type, "ready") == 0) {
            ready = true;
            failures = 0;
            learn_addresses(m);
            s->server = "connected";
            s->server_error[0] = '\0';
            s->device_id = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(m, "device"));
        }
        status_end();
        if (strcmp(type, "ready") == 0) {
            post(EV_BLE);
        }
        const char *credential = cJSON_GetStringValue(cJSON_GetObjectItem(m, "credential"));
        if (credential && credential[0] && strcmp(credential, vk_cfg.token) != 0 &&
            strlen(credential) <= VK_TOKEN_MAX) {
            strlcpy(vk_cfg.token, credential, sizeof vk_cfg.token);
            config_save();
            ESP_LOGI(TAG, "paired; using the device credential from now on");
            post(EV_CREDENTIAL);
        }
    }
    cJSON_Delete(m);
}

static void set_server_state(const char *state, const char *error)
{
    vk_status_t *s = status_begin();
    s->server = state;
    if (error) {
        strlcpy(s->server_error, error, sizeof s->server_error);
    }
    if (strcmp(state, "connected") != 0) {
        input_session[0]='\0';ble_release_all();
        s->selected = false;
    }
    status_end();
}

static void on_ws(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_websocket_event_data_t *e = data;
    switch (id) {
    case WEBSOCKET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "connected to %s", active);
        send_hello();
        break;
    case WEBSOCKET_EVENT_DATA:
        if (e->op_code == 0x08) {  // close; the payload starts with the code
            int code = e->data_len >= 2 ? ((uint8_t)e->data_ptr[0] << 8 | (uint8_t)e->data_ptr[1]) : 0;
            ESP_LOGW(TAG, "server closed the connection (%d)", code);
            if (code == CLOSE_BAD_CREDENTIAL) {
                post(EV_REJECTED);
            }
            break;
        }
        if (e->op_code != 0x01 && e->op_code != 0x00) {
            break;  // ping, pong, binary
        }
        if (e->payload_offset == 0) {
            // Sized to this message: an ESP32-C3 running Wi-Fi, Bluetooth and TLS
            // has no 32 KB block to spare, and without "ready" it never pairs.
            free(message);
            message = NULL;
            message_len = 0;
            if (e->payload_len > MESSAGE_MAX) {
                ESP_LOGW(TAG, "dropped a message of %d bytes: too long", e->payload_len);
                break;
            }
            message = malloc(e->payload_len + 1);
            if (!message) {
                ESP_LOGE(TAG, "dropped a message of %d bytes: out of memory (largest free block %u)",
                         e->payload_len, (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
            }
        }
        if (message && e->payload_offset + e->data_len <= e->payload_len) {
            memcpy(message + e->payload_offset, e->data_ptr, e->data_len);
            message_len = e->payload_offset + e->data_len;
            if (message_len >= (size_t)e->payload_len) {
                message[message_len] = '\0';
                handle_message(message);
                free(message);  // a long dictation would otherwise keep its memory
                message = NULL;
            }
        }
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
    case WEBSOCKET_EVENT_ERROR: {
        ready = false;
        char why[64] = "could not reach the server";
        bool tls = false;
        if (e && e->error_handle.esp_tls_cert_verify_flags) {
            strlcpy(why, "server certificate not trusted", sizeof why);
            tls = true;
        } else if (e && e->error_handle.esp_tls_last_esp_err == ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED) {
            strlcpy(why, "secure connection failed", sizeof why);
            tls = true;
        } else if (e && e->error_handle.esp_ws_handshake_status_code) {
            snprintf(why, sizeof why, "server answered HTTP %d", e->error_handle.esp_ws_handshake_status_code);
        }
        if (id == WEBSOCKET_EVENT_ERROR) {
            ESP_LOGW(TAG, "connection error: %s", why);
            set_server_state("error", why);
            post(tls ? EV_TLS_FAILED : EV_FAILED);
        } else {
            set_server_state("connecting", NULL);
        }
        break;
    }
    default:
        break;
    }
}

static void ws_stop(void)
{
    ready = false;
    ping_sent_us = 0;
    if (ws) {
        esp_websocket_client_stop(ws);
        esp_websocket_client_destroy(ws);
        ws = NULL;
    }
}

static void ws_start(void)
{
    ws_stop();
    if (!config_complete()) {
        set_server_state("off", "");
        return;
    }
    if (!active[0]) { strlcpy(active,vk_cfg.server,sizeof active); }
    // https://host:port → wss://host:port/api/keyboard/device/{id}
    const char *server = active;
    bool secure = strncmp(server, "https://", 8) == 0;
    const char *rest = strstr(server, "://");
    rest = rest ? rest + 3 : server;
    size_t len = strlen(rest);
    while (len && rest[len - 1] == '/') {
        len--;
    }
    free(ws_uri);
    asprintf(&ws_uri, "%s://%.*s", secure ? "wss" : "ws", (int)len, rest);
    free(ws_headers);
    asprintf(&ws_headers, "Authorization: Bearer %s\r\n", vk_cfg.token);

    esp_websocket_client_config_t c = {
        .uri = ws_uri,
        .headers = ws_headers,
        .reconnect_timeout_ms = 3000,
        .network_timeout_ms = 15000,
        .ping_interval_sec = 20,
        .pingpong_timeout_sec = 45,  // a dead link (sleep, network change) within ~a minute
        .buffer_size = 2048,
        .task_stack = 6144,
    };
    // Local addresses use the local CA first, public ones the public CAs first.
    bool with_ca = vk_cfg.ca && is_local(server) != ca_flipped;
    if (secure) {
        if (with_ca) {
            c.cert_pem = vk_cfg.ca;
            // A local address need not be named in the certificate (an IP left out
            // of VK_DOMAIN); the deployment's own CA must still have signed it.
            c.skip_cert_common_name_check = is_local(server);
        } else {
            c.crt_bundle_attach = esp_crt_bundle_attach;
        }
    }
    ws = esp_websocket_client_init(&c);
    if (!ws) {
        set_server_state("error", "out of memory");
        return;
    }
    esp_websocket_register_events(ws, WEBSOCKET_EVENT_ANY, on_ws, NULL);
    set_server_state("connecting", "");
    ESP_LOGI(TAG, "connecting to %s (%s)", ws_uri,
             !secure ? "no TLS" : with_ca ? "private CA" : "public CAs");
    esp_websocket_client_start(ws);
}

static void net_task(void *arg)
{
    bool rejected = false;
    for (;;) {
        net_event_t ev;
        if (!xQueueReceive(events, &ev, rejected ? pdMS_TO_TICKS(REJECTED_RETRY_MS) : portMAX_DELAY)) {
            rejected = false;  // retry: the user may have re-added the board
            if (wifi_up) {
                ws_start();
            }
            continue;
        }
        switch (ev) {
        case EV_WIFI_UP:
            active[0] = '\0';  // perhaps another network: choose again
            if (!ws && !rejected) {
                ws_start();
            }
            break;
        case EV_WIFI_DOWN:
            ws_stop();
            set_server_state(config_complete() ? "connecting" : "off", NULL);
            break;
        case EV_APPLY_WIFI: {
            ws_stop();
            wifi_failures = 0;
            esp_timer_stop(reconnect_timer);
            vk_status_t *st = status_begin();  // a failure was about the old settings
            st->wifi = vk_cfg.ssid[0] ? "connecting" : "off";
            st->wifi_error[0] = '\0';
            status_end();
            if (wifi_up) {
                esp_wifi_disconnect();  // reconnects with the new settings on the event
            } else if (vk_cfg.ssid[0]) {
                wifi_connect();
            } else {
                vk_status_t *s = status_begin();
                s->wifi = "off";
                status_end();
            }
            rejected = false;
            break;
        }
        case EV_APPLY_SERVER:
            rejected = false;
            active[0] = '\0';
            if (wifi_up) {
                ws_start();
            } else {
                ws_stop();
            }
            break;
        case EV_CREDENTIAL:
            if (wifi_up) {
                ws_start();
            }
            break;
        case EV_REJECTED:
            if (strcmp(active, vk_cfg.server) != 0) {
                // Another deployment at that address: back to the configured one.
                ESP_LOGW(TAG, "%s rejected the credential; using %s", active, vk_cfg.server);
                if (is_local(active)) {
                    local_failed_us = esp_timer_get_time();
                }
                strlcpy(active, vk_cfg.server, sizeof active);
                ca_flipped = false;
                failures = 0;
                ws_start();
                break;
            }
            ws_stop();
            rejected = true;
            set_server_state("rejected", "this board was removed or its setup token was replaced; set it up again");
            break;
        case EV_ROAM_CHECK:
            roam_check();
            break;
        case EV_FAILED:
            if (++failures >= FAILOVER_AFTER && ws) {
                char failed[VK_SERVER_MAX + 1];
                strlcpy(failed, active, sizeof failed);
                if (is_local(failed)) {
                    local_failed_us = esp_timer_get_time();
                }
                bool flipped = ca_flipped;
                choose_address(failed);
                if (strcmp(active, failed) != 0) {
                    ESP_LOGW(TAG, "%s does not answer; trying %s", failed, active);
                    ws_start();
                } else {
                    ca_flipped = flipped;  // the only address: the socket keeps retrying it as it is
                }
            }
            break;
        case EV_BLE:  // also sent right after "ready": a good moment for the error reports too
            send_ble_status();
            send_log_reports();
            break;
        case EV_LOG:
            log_send_pending = false;
            send_log_reports();
            break;
        case EV_WAKE:
            if (!full_speed) {
                set_full_speed(true);
            }
            break;
        case EV_PING:
            if (full_speed && esp_timer_get_time() - last_activity_us > IDLE_AFTER_MS * 1000LL) {
                set_full_speed(false);
            }
            if (!ws || !ready) {
                break;
            }
            if (!is_local(active) && local_allowed() && switch_to_local()) {
                break;
            }
            send_log_reports();
            if (ping_sent_us && esp_timer_get_time() - ping_sent_us > PONG_WITHIN_MS * 1000LL) {
                ESP_LOGW(TAG, "no answer from the server; reconnecting");
                set_server_state("connecting", "no answer from the server");
                ws_start();
            } else if (!ping_sent_us) {
                ping_sent_us = esp_timer_get_time();
                esp_websocket_client_send_text(ws, "{\"type\":\"ping\"}", 15, pdMS_TO_TICKS(2000));
            }
            break;
        case EV_TLS_FAILED:
            if (vk_cfg.ca && !ca_flipped) {
                ca_flipped = true;
                if (wifi_up) {
                    ws_start();
                }
            } else {
                post(EV_FAILED);
            }
            break;
        }
    }
}

void net_apply(bool wifi_changed, bool server_changed)
{
    if (wifi_changed) {
        post(EV_APPLY_WIFI);
    }
    if (server_changed) {vk_cfg.urls[0]='\0';config_save();}
    if (server_changed || wifi_changed) {
        post(EV_APPLY_SERVER);
    }
}

void net_start(void)
{
    events = xQueueCreate(8, sizeof(net_event_t));
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    char host[32];
    snprintf(host, sizeof host, "vkeyboard-%s", vk_machine_id() + 12);  // last 3 MAC bytes
    esp_netif_set_hostname(netif, host);
    wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wic));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));  // our own NVS keys are the source of truth
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi, NULL));
    esp_timer_create_args_t t = {.callback = reconnect_cb, .name = "wifi_retry"};
    ESP_ERROR_CHECK(esp_timer_create(&t, &reconnect_timer));
    esp_timer_create_args_t r = {.callback = roam_cb, .name = "wifi_roam"};
    ESP_ERROR_CHECK(esp_timer_create(&r, &roam_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(roam_timer, ROAM_CHECK_MS * 1000LL));
    esp_timer_create_args_t hb = {.callback = ping_cb, .name = "ws_ping"};
    ESP_ERROR_CHECK(esp_timer_create(&hb, &ping_timer));
    // Checked twice per interval, so a missing pong is noticed within ~40 s.
    ESP_ERROR_CHECK(esp_timer_start_periodic(ping_timer, PING_EVERY_MS / 2 * 1000LL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    xTaskCreate(net_task, "net", 6144, NULL, 5, NULL);
    ESP_ERROR_CHECK(esp_wifi_start());  // also when unconfigured, so the page can scan
    last_activity_us = esp_timer_get_time();  // full speed after a restart, until left alone
    set_full_speed(true);
}
