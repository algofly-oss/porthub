// Serial link to the setup page: UART0 (the USB-to-serial chip on dev
// boards) and, on chips that have it, the built-in USB serial port (most
// ESP32-C3 boards). Both are read; everything is written to both, so the page
// works with whichever one the board's USB socket is wired to.
//
// Logs go through the same lock, so a log line never splits a "@vk" line.
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "esp_log.h"
#include "sdkconfig.h"
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
#include "driver/usb_serial_jtag.h"
#endif
#include "vk.h"

#define IO_LINE_MAX 8192  // a config command carries a CA certificate (~1 KB)

static SemaphoreHandle_t out_lock;
static io_line_handler_t on_line;

static void write_raw(const char *data, size_t len)
{
    uart_write_bytes(UART_NUM_0, data, len);
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
    // Without a host reading, writes would block until the timeout.
    if (usb_serial_jtag_is_connected()) {
        usb_serial_jtag_write_bytes(data, len, pdMS_TO_TICKS(20));
    }
#endif
}

static void write_line(const char *prefix, const char *text, size_t len)
{
    xSemaphoreTake(out_lock, portMAX_DELAY);
    if (prefix) {
        write_raw(prefix, strlen(prefix));
    }
    write_raw(text, len);
    xSemaphoreGive(out_lock);
}

static int log_vprintf(const char *format, va_list args)
{
    char buf[256];
    int n = vsnprintf(buf, sizeof buf, format, args);
    if (n > 0) {
        write_line(NULL, buf, n < (int)sizeof buf ? (size_t)n : sizeof buf - 1);
        // Errors and warnings also go to the server (after a colour code, if any).
        const char *p = buf[0] == '\x1b' ? strchr(buf, 'm') : NULL;
        p = p ? p + 1 : buf;
        bool line = (p[0] == 'E' || p[0] == 'W' || p[0] == 'I') && p[1] == ' ' && p[2] == '(';
        if (line && (p[0] != 'I' || net_log_streaming())) {
            net_report_log(p);
        }
    }
    return n;
}

void io_event(cJSON *event)
{
    char *text = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    if (!text) {
        return;
    }
    size_t len = strlen(text);
    xSemaphoreTake(out_lock, portMAX_DELAY);
    write_raw("@vk ", 4);
    write_raw(text, len);
    write_raw("\r\n", 2);
    xSemaphoreGive(out_lock);
    free(text);
}

typedef int (*read_fn)(uint8_t *buf, size_t len);

static int read_uart(uint8_t *buf, size_t len)
{
    return uart_read_bytes(UART_NUM_0, buf, len, pdMS_TO_TICKS(20));
}

#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
static int read_usb(uint8_t *buf, size_t len)
{
    return usb_serial_jtag_read_bytes(buf, len, pdMS_TO_TICKS(20));
}
#endif

static void reader_task(void *arg)
{
    read_fn read = (read_fn)arg;
    char *line = malloc(IO_LINE_MAX);
    size_t len = 0;
    bool overflow = false;
    uint8_t chunk[128];
    for (;;) {
        int n = read(chunk, sizeof chunk);
        for (int i = 0; i < n; i++) {
            char c = (char)chunk[i];
            if (c == '\n' || c == '\r') {
                if (len && !overflow && line[0] == '{') {
                    line[len] = '\0';
                    on_line(line);
                }
                len = 0;
                overflow = false;
            } else if (len < IO_LINE_MAX - 1) {
                line[len++] = c;
            } else {
                overflow = true;  // dropped whole; the page retries
            }
        }
    }
}

void io_init(io_line_handler_t handler)
{
    on_line = handler;
    out_lock = xSemaphoreCreateMutex();
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 2 * 1024, 4 * 1024, 0, NULL, 0));
    uart_vfs_dev_use_driver(UART_NUM_0);  // stray printf() goes through the driver too
    xTaskCreate(reader_task, "io_uart", 6144, (void *)read_uart, 5, NULL);
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
    usb_serial_jtag_driver_config_t usb = {.rx_buffer_size = 2048, .tx_buffer_size = 4096};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb));
    xTaskCreate(reader_task, "io_usb", 6144, (void *)read_usb, 5, NULL);
#endif
    esp_log_set_vprintf(log_vprintf);
}
