// Bluetooth LE keyboard (HID over GATT) and the typing queue.
//
// Pairing is "Just Works" with bonding: the user adds the board once in the
// target computer's Bluetooth settings, and it reconnects by itself after.
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_bt.h"
#include "esp_hidd.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_nimble_hci.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "vk.h"

static const char *TAG = "ble";

#define RETRY_MS 2            // when the stack's buffers are full
#define RETRY_LIMIT 1000      // ~2 s, then the report is dropped
#define REPORT_ID 1
#define MOUSE_REPORT_ID 2
#define APPEARANCE_KEYBOARD 0x03C1

void ble_store_config_init(void);

// Standard boot-compatible keyboard: modifiers, reserved, six keys; LEDs out.
static const uint8_t report_map[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,  // Generic Desktop, Keyboard, Collection (Application)
    0x85, REPORT_ID,                     //   Report ID
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,  //   Keyboard usages E0–E7 (modifiers)
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,  // 8 × 1 bit, Input
    0x95, 0x01, 0x75, 0x08, 0x81, 0x03,  //   reserved byte
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,  // 5 LEDs, Output
    0x95, 0x01, 0x75, 0x03, 0x91, 0x03,  //   LED padding
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x73,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x73, 0x81, 0x00,  // 6 key codes, Input (Array)
    0xC0,
    // Mouse, for the web app's touchpad: 3 buttons, X, Y, wheel, horizontal pan.
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01,  // Generic Desktop, Mouse, Collection (Application)
    0x85, MOUSE_REPORT_ID,               //   Report ID
    0x09, 0x01, 0xA1, 0x00,              //   Pointer, Collection (Physical)
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,  // buttons 1–3
    0x95, 0x01, 0x75, 0x05, 0x81, 0x03,  //     padding
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38,  // X, Y, Wheel
    0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06,  // -127..127, Input (Relative)
    0x05, 0x0C, 0x0A, 0x38, 0x02,        //     Consumer: AC Pan (horizontal scroll)
    0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06,
    0xC0, 0xC0,
};

static esp_hid_raw_report_map_t report_maps[] = {{.data = report_map, .len = sizeof report_map}};

static esp_hid_device_config_t hid_config = {
    .vendor_id = 0x16C0,  // pid.codes shared test VID/PID for keyboards
    .product_id = 0x05DF,
    .version = 0x0100,
    .device_name = "PortHub keyboard",
    .manufacturer_name = "PortHub keyboard",
    .serial_number = "1",
    .report_maps = report_maps,
    .report_maps_len = 1,
};

static esp_hidd_dev_t *hid;
static volatile bool connected;
// Turned off from the web app: no advertising, no connection, so an iPad or
// phone shows its own on-screen keyboard again. Not saved: a restart turns it on.
static volatile bool enabled = true;
// Pairing mode (from the web app): until then, computers paired before are
// refused, so they cannot take the board back before a new device pairs.
static volatile int64_t pairing_until_us;

static bool pairing(void)
{
    return pairing_until_us && esp_timer_get_time() < pairing_until_us;
}

// In pairing mode, a connection that gets encrypted without pairing is a known
// device reconnecting with its old keys: it is dropped to make room. A device
// that pairs (new, or pairing again after forgetting the board) is kept; the
// check waits a moment, as "pairing complete" may follow the encryption event.
static esp_timer_handle_t reconnect_check;
static uint16_t check_handle;
static volatile bool paired_now;

static void reconnect_check_cb(void *arg)
{
    if (!paired_now && pairing()) {
        ESP_LOGI(TAG, "pairing mode: a known device reconnected with its old keys; making room for a new one");
        ble_gap_terminate(check_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
}
static uint8_t own_addr_type;
static char name[VK_NAME_MAX + 1] = "PortHub keyboard";

// ---- Advertising ----

static int gap_event(struct ble_gap_event *event, void *arg);

// Why a connection ended, in words: warnings reach the server's client log
// (GET /api/client-errors), so a keyboard that comes and goes can be explained.
static const char *disconnect_reason(int reason)
{
    switch (reason) {
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_CONN_SPVN_TMO:
        return "the signal was lost (out of range, or interference)";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_REM_USER_CONN_TERM:
        return "the device closed the connection";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_RD_CONN_TERM_PWROFF:
        return "the device turned Bluetooth off";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_RD_CONN_TERM_RESRCS:
        return "the device ran out of resources";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_CONN_TERM_LOCAL:
        return "the board closed the connection";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_CONN_ESTABLISHMENT:
        return "the connection could not be set up";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_LMP_LL_RSP_TMO:
        return "the device stopped answering";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_INSTANT_PASSED:
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_DIFF_TRANS_COLL:
        return "a timing error on the link (usually weak signal)";
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_AUTH_FAIL:
    case BLE_HS_ERR_HCI_BASE + BLE_ERR_PINKEY_MISSING:
        return "the pairing keys did not match (pair again)";
    default:
        return "another reason";
    }
}

static int64_t connected_at_us;
static uint16_t conn_handle;
static int64_t report_every_us = 15 * 1000LL;  // the connection interval: a pointer report each
static volatile int8_t last_rssi;  // read every second while connected; logged when the link drops

// In use, the shortest connection interval the host allows (7.5 ms; Apple
// devices refuse that, and get 15 ms on the next try): it sets the typing speed. Idle, a longer one, and the
// board may skip events with nothing to send: the radio wakes far less often.
// The first keystroke still goes out within 50 ms, and wakes it (net.c).
static volatile bool fast = true;
// The host may refuse a change (busy with another procedure) or pick another
// interval: asked again a few times, so a refusal does not leave it slow.
#define INTERVAL_TRIES 3
static esp_timer_handle_t interval_retry;
static int interval_tries;
static bool apple_interval;  // the host refused 7.5 ms; ask for exactly 15 (Apple's minimum)

static void request_interval(uint16_t handle)
{
    struct ble_gap_upd_params p = {.itvl_min = apple_interval ? 12 : 6, .itvl_max = 12, .latency = 0,
                                   .supervision_timeout = 400};
    if (!fast) {
        p.itvl_min = 24;  // 30 ms
        p.itvl_max = 40;  // 50 ms
        p.latency = 4;
    }
    ble_gap_update_params(handle, &p);
}

void ble_set_fast(bool on)
{
    if (fast == on) {
        return;
    }
    fast = on;
    interval_tries = 0;
    if (connected) {
        request_interval(conn_handle);
    }
}

static void interval_retry_cb(void *arg)
{
    if (connected) {
        request_interval(conn_handle);
    }
}

static void advertise(void)
{
    if (!enabled) {
        vk_status_t *s = status_begin();
        s->ble = "off";
        s->ble_peer[0] = '\0';
        status_end();
        return;
    }
    if (connected || !ble_hs_synced()) {
        return;
    }
    ble_gap_adv_stop();
    // The name goes in the scan response: 31 bytes are not enough for both.
    struct ble_hs_adv_fields fields = {0};
    ble_uuid16_t hid_uuid = BLE_UUID16_INIT(0x1812);
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.appearance = APPEARANCE_KEYBOARD;
    fields.appearance_is_present = 1;
    fields.uuids16 = &hid_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    int rc = ble_gap_adv_set_fields(&fields);
    struct ble_hs_adv_fields rsp = {0};
    rsp.name = (uint8_t *)name;
    rsp.name_len = strlen(name);
    rsp.name_is_complete = 1;
    if (!rc) rc = ble_gap_adv_rsp_set_fields(&rsp);
    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = BLE_GAP_ADV_ITVL_MS(30),
        .itvl_max = BLE_GAP_ADV_ITVL_MS(50),
    };
    if (!rc) rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "advertising failed: %d", rc);
        return;
    }
    vk_status_t *s = status_begin();
    s->ble = pairing() ? "pairing" : "advertising";
    s->ble_peer[0] = '\0';
    status_end();
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_conn_desc desc;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            ESP_LOGW(TAG, "connection failed: %d", event->connect.status);
            advertise();
        } else if (ble_gap_conn_find(event->connect.conn_handle, &desc) == 0) {
            // A computer paired before: encrypt right away with the stored keys,
            // so its first reads of the keyboard's attributes succeed.
            struct ble_store_key_sec key = {.peer_addr = desc.peer_id_addr};
            struct ble_store_value_sec bond;
            bool bonded = ble_store_read_peer_sec(&key, &bond) == 0;
            int8_t rssi = 0;
            ble_gap_conn_rssi(event->connect.conn_handle, &rssi);
            ESP_LOGW(TAG, "Bluetooth: connected to %s device (signal %d dBm)", bonded ? "a paired" : "a new", rssi);
            connected_at_us = esp_timer_get_time();
            conn_handle = event->connect.conn_handle;
            interval_tries = 0;
            apple_interval = false;
            last_rssi = rssi;
            connected = true;
            paired_now = false;
            vk_status_t *s = status_begin();
            s->ble = "connected";
            status_end();
            if (bonded && !pairing()) {  // in pairing mode, let the device choose: pair again, or reconnect (dropped)
                ble_gap_security_initiate(event->connect.conn_handle);
            }
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        // Here, not from esp_hidd's events: those come from another task, and a
        // late one from a failed attempt could undo a newer connection.
        if (connected) {
            int secs = (int)((esp_timer_get_time() - connected_at_us) / 1000000);
            ESP_LOGW(TAG, "Bluetooth: disconnected after %d:%02d:%02d: %s (0x%x); last signal %d dBm",
                     secs / 3600, secs / 60 % 60, secs % 60, disconnect_reason(event->disconnect.reason),
                     event->disconnect.reason, last_rssi);
        } else {
            ESP_LOGI(TAG, "disconnected, reason 0x%x", event->disconnect.reason);
        }
        connected = false;
        advertise();
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "encryption %s (%d)", event->enc_change.status == 0 ? "on" : "failed", event->enc_change.status);
        if (event->enc_change.status == 0 && pairing() && !paired_now) {
            check_handle = event->enc_change.conn_handle;
            esp_timer_stop(reconnect_check);
            esp_timer_start_once(reconnect_check, 1500 * 1000);
        }
        if (event->enc_change.status == 0 && ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0) {
            vk_status_t *s = status_begin();
            s->ble = "connected";
            const uint8_t *a = desc.peer_id_addr.val;
            snprintf(s->ble_peer, sizeof s->ble_peer, "%02X:%02X:%02X:%02X:%02X:%02X",
                     a[5], a[4], a[3], a[2], a[1], a[0]);
            status_end();
            request_interval(event->enc_change.conn_handle);
        }
        return 0;
    case BLE_GAP_EVENT_CONN_UPDATE:
        if (ble_gap_conn_find(event->conn_update.conn_handle, &desc) == 0) {
            if (event->conn_update.status != 0) {
                apple_interval = apple_interval || fast;
                ESP_LOGI(TAG, "connection interval change refused (%d); still %d.%02d ms", event->conn_update.status,
                         desc.conn_itvl * 125 / 100, desc.conn_itvl * 125 % 100);
            } else {
                ESP_LOGI(TAG, "connection interval %d.%02d ms", desc.conn_itvl * 125 / 100, desc.conn_itvl * 125 % 100);
            }
            report_every_us = desc.conn_itvl * 1250LL;
            bool off = fast ? desc.conn_itvl > 12 : desc.conn_itvl < 24;
            if (off && connected && interval_tries < INTERVAL_TRIES) {
                interval_tries++;
                esp_timer_stop(interval_retry);
                esp_timer_start_once(interval_retry, 2000 * 1000);
            }
        }
        return 0;
    case BLE_GAP_EVENT_PARING_COMPLETE:  // (sic, NimBLE's name)
        ESP_LOGI(TAG, "pairing %s (%d)", event->pairing_complete.status == 0 ? "complete" : "failed",
                 event->pairing_complete.status);
        if (event->pairing_complete.status == 0) {
            paired_now = true;
            if (pairing()) {
                pairing_until_us = 0;
                ESP_LOGI(TAG, "pairing mode: a device paired; back to normal");
            }
        }
        return 0;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        // The computer forgot the board and pairs again: drop the old bond.
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
            ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        return 0;
    }
    return 0;
}

static void hid_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    switch ((esp_hidd_event_t)id) {
    case ESP_HIDD_START_EVENT:
        advertise();
        break;
    case ESP_HIDD_CONNECT_EVENT:  // the connection state comes from gap_event
        ESP_LOGD(TAG, "HID connected");
        break;
    case ESP_HIDD_DISCONNECT_EVENT:
        ESP_LOGD(TAG, "HID disconnected");
        break;
    default:
        break;
    }
}

static void host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

// ---- Typing ----

typedef struct {
    char *text;   // text to type, or NULL for a key or a pointer action
    int8_t key;   // HID usage of a named key
    uint8_t mod;  // modifiers pressed with it (ctrl+c)
    char state;   // 'p'ress, 'd'own, 'u'p; pointer: 'm'ove, 'c'lick, 's'croll, 'P'ress, 'R'elease
    int16_t dx, dy;   // pointer motion or scroll steps
    uint8_t buttons;  // pointer click: 1 left, 2 right, 4 middle
} job_t;

static QueueHandle_t jobs;
static uint8_t held_mod;
static volatile int64_t last_key_us;
static volatile unsigned input_generation;
static uint8_t held;  // a key kept down by "down"/"hold" until "up"

// As fast as the link takes them: no fixed delay, only waiting while the
// stack's buffers are full. Notifications arrive in order, and every report
// reaches the host.
static void send_input(uint8_t id, uint8_t *report, size_t len)
{
    for (int attempt = 0; attempt < RETRY_LIMIT; attempt++) {
        if (!connected) {
            return;
        }
        if (esp_hidd_dev_input_set(hid, 0, id, report, len) == ESP_OK) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(RETRY_MS));
    }
    ESP_LOGW(TAG, "report dropped: the link is stalled");
}

static void send_report(uint8_t mod, uint8_t code)
{
    uint8_t report[8] = {mod, 0, code, 0, 0, 0, 0, 0};
    send_input(REPORT_ID, report, sizeof report);
}

static void send_mouse(uint8_t buttons, int8_t x, int8_t y, int8_t wheel, int8_t pan)
{
    uint8_t report[5] = {buttons, (uint8_t)x, (uint8_t)y, (uint8_t)wheel, (uint8_t)pan};
    send_input(MOUSE_REPORT_ID, report, sizeof report);
}

// Buttons held for a drag: they stay set in every report, so motion drags.
static uint8_t held_buttons;
static int64_t last_pointer_us;
#define DRAG_TIMEOUT_US (5 * 1000 * 1000LL)  // no input for this long: let go

static bool is_pointer(const job_t *job)
{
    return job->state == 'm' || job->state == 'c' || job->state == 's' || job->state == 'P' || job->state == 'R';
}

static int8_t step(int *rest)
{
    int s = *rest > 127 ? 127 : *rest < -127 ? -127 : *rest;
    *rest -= s;
    return (int8_t)s;
}

// Touchpad motion, played out evenly. Wi-Fi shares the radio with Bluetooth,
// which holds it for ~60 ms of every ~100 ms while connected, so moves sent
// at 60 per second arrive in bursts ten times a second. Sent as they come, the
// pointer would jump at that rate; instead each burst is spread, one report per
// connection interval, over the time until the next burst is expected. That
// time follows the gaps seen: ~100 ms on such a link, down to a frame on a
// smooth one.
#define PACE_MIN_US (16 * 1000LL)
#define PACE_MAX_US (120 * 1000LL)
#define GESTURE_GAP_US (300 * 1000LL)  // a longer pause starts another movement
static int pending_dx, pending_dy;
static int64_t pace_horizon_us = 100 * 1000LL;  // expected time until the next moves
static int64_t pace_deadline_us;                // all pending motion out by then
static int64_t next_report_us;
static int64_t last_move_us;

static void pace_add(int dx, int dy, int64_t now)
{
    int64_t gap = now - last_move_us;
    last_move_us = now;
    if (gap < GESTURE_GAP_US) {  // up at once to a longer gap, down slowly
        int64_t h = pace_horizon_us - gap / 4;
        pace_horizon_us = gap > h ? gap : h;
        pace_horizon_us = pace_horizon_us < PACE_MIN_US ? PACE_MIN_US
                        : pace_horizon_us > PACE_MAX_US ? PACE_MAX_US : pace_horizon_us;
    }
    if (!pending_dx && !pending_dy && next_report_us < now) {
        next_report_us = now;  // the first report of a movement goes out at once
    }
    pending_dx += dx;
    pending_dy += dy;
    pace_deadline_us = now + pace_horizon_us;
}

// One report's share of the pending motion: what is left, divided over the
// reports that fit before the deadline (a report carries at most ±127 per axis).
static void pace_report(int64_t now)
{
    int64_t reports = (pace_deadline_us - now) / report_every_us;
    int n = reports < 1 ? 1 : (int)reports;
    int x = pending_dx / n, y = pending_dy / n;
    if (!x && !y) {  // less than one count per report: move one count at a time
        x = (pending_dx > 0) - (pending_dx < 0);
        y = (pending_dy > 0) - (pending_dy < 0);
    }
    x = x > 127 ? 127 : x < -127 ? -127 : x;
    y = y > 127 ? 127 : y < -127 ? -127 : y;
    pending_dx -= x;
    pending_dy -= y;
    send_mouse(held_buttons, (int8_t)x, (int8_t)y, 0, 0);
    next_report_us = now + report_every_us;
}

// Clicks, drags and scrolling wait for the motion before them.
static void pace_flush(void)
{
    while (pending_dx || pending_dy) {
        int8_t x = step(&pending_dx), y = step(&pending_dy);
        send_mouse(held_buttons, x, y, 0, 0);
    }
}

static void pointer_job(const job_t *job)
{
    int dx = job->dx, dy = job->dy;
    last_pointer_us = esp_timer_get_time();
    if (job->state == 'm') {
        pace_add(dx, dy, last_pointer_us);
        return;
    }
    pace_flush();
    switch (job->state) {
    case 'c':
        send_mouse(held_buttons | job->buttons, 0, 0, 0, 0);
        send_mouse(held_buttons, 0, 0, 0, 0);
        break;
    case 'P':
        held_buttons |= job->buttons;
        send_mouse(held_buttons, 0, 0, 0, 0);
        break;
    case 'R':
        held_buttons &= ~job->buttons;
        send_mouse(held_buttons, 0, 0, 0, 0);
        break;
    case 's':  // the wheel counts up as positive; dy > 0 scrolls down
        dy = -dy;
        while (dx || dy) {
            int8_t wheel = step(&dy), pan = step(&dx);
            send_mouse(held_buttons, 0, 0, wheel, pan);
        }
        break;
    }
}

static void stroke(uint8_t mod, uint8_t code)
{
    send_report(mod, code);
    send_report(0, held);
}

// Decodes one UTF-8 character; returns its length (1 for invalid bytes).
static int utf8_next(const char *s, uint32_t *cp)
{
    const uint8_t *u = (const uint8_t *)s;
    int len = u[0] < 0x80 ? 1 : (u[0] >> 5) == 6 ? 2 : (u[0] >> 4) == 14 ? 3 : (u[0] >> 3) == 30 ? 4 : 0;
    if (!len) {
        *cp = 0xFFFD;
        return 1;
    }
    *cp = len == 1 ? u[0] : u[0] & (0x7F >> len);
    for (int i = 1; i < len; i++) {
        if ((u[i] & 0xC0) != 0x80) {
            *cp = 0xFFFD;
            return i;
        }
        *cp = *cp << 6 | (u[i] & 0x3F);
    }
    return len;
}

// One report per character: going from one key straight to the next releases
// the first. A release report is only needed between two presses of the same
// key ("ll"), and a Shift change gets its own report first, so a capital
// letter can never come out lower-case.
static void type_text(const char *text)
{
    unsigned generation=input_generation;
    int typed = 0, skipped = 0;
    uint8_t cur_mod = 0, cur_code = 0;  // what the host sees pressed
    int64_t start = esp_timer_get_time();
    for (const char *p = text; *p && generation==input_generation;) {
        uint32_t cp;
        p += utf8_next(p, &cp);
        vk_stroke_t strokes[3];
        int n = keymap_lookup(cp, strokes);
        if (!n) {
            skipped++;
            continue;
        }
        for (int i = 0; i < n; i++) {
            uint8_t mod = strokes[i].mod, code = strokes[i].code;
            if (held) {  // a key held with "down": keep the old press-and-release
                stroke(mod, code);
                continue;
            }
            if (code == cur_code || mod != cur_mod) {
                send_report(mod, 0);
            }
            send_report(mod, code);
            cur_mod = mod;
            cur_code = code;
        }
        typed++;
    }
    if (cur_code || cur_mod) {
        send_report(0, held);
    }
    int ms = (int)((esp_timer_get_time() - start) / 1000);
    // Only counts are logged: dictated text can contain passwords.
    if (skipped) {
        ESP_LOGW(TAG, "typed %d characters in %d ms; %d have no key on a US keyboard", typed, ms, skipped);
    } else {
        ESP_LOGI(TAG, "typed %d characters in %d ms", typed, ms);
    }
}

static void typing_task(void *arg)
{
    job_t job;
    for (;;) {
        TickType_t wait = pdMS_TO_TICKS(1000);
        if (pending_dx || pending_dy) {
            int64_t now = esp_timer_get_time();
            if (!connected) {
                pending_dx = pending_dy = 0;
            } else if (now >= next_report_us) {
                pace_report(now);
                continue;
            } else {
                wait = pdMS_TO_TICKS((next_report_us - now + 999) / 1000);
            }
        }
        if (xQueueReceive(jobs, &job, wait) != pdTRUE) {
            if (pending_dx || pending_dy) {
                continue;  // time for the next report
            }
            if (pairing_until_us && !pairing()) {  // the window ended without a new device
                pairing_until_us = 0;
                ESP_LOGI(TAG, "pairing mode ended");
                if (!connected) {
                    advertise();
                }
            }
            int8_t rssi;
            if (connected && ble_gap_conn_rssi(conn_handle, &rssi) == 0) {
                last_rssi = rssi;
            }
            if ((held || held_mod) && esp_timer_get_time()-last_key_us>5000000 && connected) {held=0;held_mod=0;send_report(0,0);}
            // A drag whose release never came (the phone lost its connection).
            if (held_buttons && esp_timer_get_time() - last_pointer_us > DRAG_TIMEOUT_US && connected) {
                held_buttons = 0;
                send_mouse(0, 0, 0, 0, 0);
            }
            continue;
        }
        if (job.state=='x') {held=0;held_mod=0;held_buttons=0;if(connected){send_report(0,0);send_mouse(0,0,0,0,0);}free(job.text);continue;}
        if (!connected) {
            bool pointer = is_pointer(&job);
            if (!pointer) {  // pointer motion would flood the log
                ESP_LOGW(TAG, "not typed: no computer is connected over Bluetooth");
            }
            free(job.text);
            continue;
        }
        if (is_pointer(&job)) {
            pointer_job(&job);
        } else if (job.text) {
            type_text(job.text);
            free(job.text);
        } else if (job.state == 'p') {
            stroke(job.mod, job.key);
        } else if (job.state == 'd') {
            last_key_us=esp_timer_get_time();
            if(job.key>=224 && job.key<=231) held_mod|=1u<<(job.key-224);else held=job.key;
            send_report(held_mod,held);
        } else {
            if(job.key>=224 && job.key<=231) held_mod&=~(1u<<(job.key-224));else if(held==job.key) held=0;
            send_report(held_mod,held);
        }
    }
}

void ble_release_all(void)
{
    input_generation++;
    job_t old;
    while(jobs && xQueueReceive(jobs,&old,0)==pdTRUE) free(old.text);
    job_t reset={.state='x'};
    if(jobs) xQueueSendToFront(jobs,&reset,0);
}
bool ble_type(const char *text)
{
    if(!connected || !enabled || !jobs) return false;
    // Reject an unsupported segment before typing a partial command.
    for(const char *p=text;*p;){uint32_t cp;p+=utf8_next(p,&cp);vk_stroke_t strokes[3];if(!keymap_lookup(cp,strokes))return false;}
    job_t job={.text=strdup(text)};
    if(!job.text)return false;
    if(xQueueSend(jobs,&job,0)!=pdTRUE){free(job.text);return false;}
    return true;
}

// HID modifier bits (left-hand keys).
#define MOD_CTRL 0x01
#define MOD_SHIFT 0x02
#define MOD_ALT 0x04
#define MOD_GUI 0x08  // Command on a Mac, the Windows key, Super

// "ctrl+alt+shift+meta+<key>": modifiers, then a named key, a letter or a digit.
// Returns false for anything else (a plain key name).
static bool parse_combo(const char *name, uint8_t *mod, uint8_t *code)
{
    const char *key = strrchr(name, '+');
    if (!key || !key[1]) {
        return false;
    }
    *mod = 0;
    for (const char *p = name; p < key;) {
        const char *end = strchr(p, '+');
        size_t len = end - p;
        if (len == 4 && strncmp(p, "ctrl", 4) == 0) *mod |= MOD_CTRL;
        else if (len == 3 && strncmp(p, "alt", 3) == 0) *mod |= MOD_ALT;
        else if (len == 5 && strncmp(p, "shift", 5) == 0) *mod |= MOD_SHIFT;
        else if (len == 4 && strncmp(p, "meta", 4) == 0) *mod |= MOD_GUI;
        else return false;
        p = end + 1;
    }
    key++;
    int named = keymap_named(key);
    if (named >= 0) {
        *code = named;
        return true;
    }
    vk_stroke_t stroke[3];
    if (strlen(key) == 1 && ((key[0] >= 'a' && key[0] <= 'z') || (key[0] >= '0' && key[0] <= '9')) &&
        keymap_lookup((uint8_t)key[0], stroke) == 1) {
        *code = stroke[0].code;
        return true;
    }
    return false;
}

bool ble_key(const char *key, const char *state)
{
    if(!connected || !enabled || !jobs) return false;
    uint8_t mod, combo_code;
    if (parse_combo(key, &mod, &combo_code)) {  // always a press, as one chord
        if (strcmp(state, "up") != 0) {
            job_t job = {.key = combo_code, .mod = mod, .state = 'p'};
            return xQueueSend(jobs, &job, 0)==pdTRUE;
        }
        return true;
    }
    int code = keymap_named(key);
    if(code<0 && strlen(key)==1){vk_stroke_t strokes[3];if(keymap_lookup((uint8_t)key[0],strokes)==1)code=strokes[0].code;}
    if(strcmp(key,"ctrl")==0)code=224;
    if(strcmp(key,"shift")==0)code=225;
    if(strcmp(key,"alt")==0)code=226;
    if(strcmp(key,"meta")==0)code=227;
    if (code < 0) return false;
    job_t job = {.key = code, .state = strcmp(state, "up") == 0 ? 'u'
                                    : (strcmp(state, "down") == 0 || strcmp(state, "hold") == 0) ? 'd' : 'p'};
    return xQueueSend(jobs, &job, 0)==pdTRUE;
}

bool ble_pointer(const char *action, int dx, int dy, const char *button)
{
    if(!connected || !enabled || !jobs) return false;
    job_t job = {.dx = dx, .dy = dy};
    if (strcmp(action, "move") == 0) {
        job.state = 'm';
    } else if (strcmp(action, "scroll") == 0) {
        job.state = 's';
    } else if (button && (strcmp(action, "click") == 0 || strcmp(action, "press") == 0 || strcmp(action, "release") == 0)) {
        job.state = action[0] == 'c' ? 'c' : action[0] == 'p' ? 'P' : 'R';
        job.buttons = strcmp(button, "right") == 0 ? 2 : strcmp(button, "middle") == 0 ? 4 : 1;
    } else {
        return false;
    }
    return xQueueSend(jobs, &job, 0)==pdTRUE;  // a full queue drops pointer motion: it is superseded anyway
}

// ---- Setup ----

static void (*hid_sync)(void);  // esp_hidd's: it posts ESP_HIDD_START_EVENT

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    ble_hs_id_infer_auto(0, &own_addr_type);
    hid_sync();
}

void ble_set_name(const char *new_name)
{
    strlcpy(name, new_name && new_name[0] ? new_name : "PortHub keyboard", sizeof name);
    ble_svc_gap_device_name_set(name);
    advertise();  // takes effect for computers that have not paired yet
}

void ble_set_enabled(bool on)
{
    if (on == enabled) {
        return;
    }
    enabled = on;
    ESP_LOGI(TAG, "Bluetooth keyboard %s", on ? "on" : "off (the device can use its on-screen keyboard)");
    if (!on) {
        ble_gap_adv_stop();
        struct ble_gap_conn_desc desc;
        for (uint16_t handle = 0; handle < 8; handle++) {
            if (ble_gap_conn_find(handle, &desc) == 0) {
                ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM);
            }
        }
    }
    advertise();  // on: a paired device reconnects by itself; off: reports "off"
}

void ble_pairing_mode(int seconds)
{
    pairing_until_us = esp_timer_get_time() + seconds * 1000000LL;
    ESP_LOGI(TAG, "pairing mode for %d s: add \"%s\" on the new device", seconds, name);
    enabled = true;
    struct ble_gap_conn_desc desc;
    bool dropped = false;
    for (uint16_t handle = 0; handle < 8; handle++) {
        if (ble_gap_conn_find(handle, &desc) == 0) {
            ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM);
            dropped = true;
        }
    }
    if (!dropped) {
        advertise();  // otherwise the disconnect event does
    }
}

void ble_forget(void)
{
    ble_store_clear();
    struct ble_gap_conn_desc desc;
    for (uint16_t handle = 0; handle < 8; handle++) {
        if (ble_gap_conn_find(handle, &desc) == 0) {
            ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM);
        }
    }
    advertise();
}

void ble_start(void)
{
    esp_timer_create_args_t rc = {.callback = reconnect_check_cb, .name = "pair_check"};
    ESP_ERROR_CHECK(esp_timer_create(&rc, &reconnect_check));
    esp_timer_create_args_t ir = {.callback = interval_retry_cb, .name = "ble_interval"};
    ESP_ERROR_CHECK(esp_timer_create(&ir, &interval_retry));
    jobs = xQueueCreate(64, sizeof(job_t));
    xTaskCreate(typing_task, "typing", 4096, NULL, 6, NULL);
    if (vk_cfg.name[0]) {
        strlcpy(name, vk_cfg.name, sizeof name);
    }

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    esp_bt_controller_config_t bt = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_nimble_init());

    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    hid_config.device_name = name;
    ESP_ERROR_CHECK(esp_hidd_dev_init(&hid_config, ESP_HID_TRANSPORT_BLE, hid_event, &hid));
    // Resolve our address before esp_hidd's sync callback starts advertising.
    hid_sync = ble_hs_cfg.sync_cb;
    ble_hs_cfg.sync_cb = on_sync;
    ble_svc_gap_device_name_set(name);
    ble_svc_gap_device_appearance_set(APPEARANCE_KEYBOARD);
    ble_store_config_init();
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ESP_ERROR_CHECK(esp_nimble_enable(host_task));
}
