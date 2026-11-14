idf_component_register(SRCS "main.c" "io.c" "config.c" "net.c" "ble.c" "keymap.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_hid bt nvs_flash esp_wifi esp_netif esp_event json
                                esp_driver_uart esp_driver_usb_serial_jtag mbedtls esp_app_format
                                spi_flash esp_timer)
