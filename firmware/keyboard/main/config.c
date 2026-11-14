// Settings in NVS, namespace "vk". Erasing the flash from the setup page
// clears them; updating the firmware keeps them.
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "vk.h"

static const char *TAG = "config";

vk_config_t vk_cfg;

static void get_str(nvs_handle_t nvs, const char *key, char *out, size_t size)
{
    size_t len = size;
    if (nvs_get_str(nvs, key, out, &len) != ESP_OK) {
        out[0] = '\0';
    }
}

void config_load(void)
{
    nvs_handle_t nvs;
    free(vk_cfg.ca);
    memset(&vk_cfg, 0, sizeof vk_cfg);
    if (nvs_open("vk", NVS_READONLY, &nvs) != ESP_OK) {
        return;  // nothing saved yet
    }
    get_str(nvs, "ssid", vk_cfg.ssid, sizeof vk_cfg.ssid);
    get_str(nvs, "pass", vk_cfg.pass, sizeof vk_cfg.pass);
    get_str(nvs, "server", vk_cfg.server, sizeof vk_cfg.server);
    get_str(nvs, "token", vk_cfg.token, sizeof vk_cfg.token);
    get_str(nvs, "name", vk_cfg.name, sizeof vk_cfg.name);
    get_str(nvs, "urls", vk_cfg.urls, sizeof vk_cfg.urls);
    size_t len = 0;
    if (nvs_get_str(nvs, "ca", NULL, &len) == ESP_OK && len > 1) {
        vk_cfg.ca = malloc(len);
        if (vk_cfg.ca && nvs_get_str(nvs, "ca", vk_cfg.ca, &len) != ESP_OK) {
            free(vk_cfg.ca);
            vk_cfg.ca = NULL;
        }
    }
    nvs_close(nvs);
}

bool config_save(void)
{
    nvs_handle_t nvs;
    if (nvs_open("vk", NVS_READWRITE, &nvs) != ESP_OK) {
        return false;
    }
    esp_err_t err = nvs_set_str(nvs, "ssid", vk_cfg.ssid);
    if (!err) err = nvs_set_str(nvs, "pass", vk_cfg.pass);
    if (!err) err = nvs_set_str(nvs, "server", vk_cfg.server);
    if (!err) err = nvs_set_str(nvs, "token", vk_cfg.token);
    if (!err) err = nvs_set_str(nvs, "name", vk_cfg.name);
    if (!err) err = nvs_set_str(nvs, "urls", vk_cfg.urls);
    if (!err) err = vk_cfg.ca ? nvs_set_str(nvs, "ca", vk_cfg.ca) : nvs_erase_key(nvs, "ca");
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;  // erasing a CA that was never saved
    if (!err) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err) {
        ESP_LOGE(TAG, "could not save settings: %s", esp_err_to_name(err));
    }
    return !err;
}

void config_erase(void)
{
    nvs_handle_t nvs;
    if (nvs_open("vk", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    config_load();
}

bool config_complete(void)
{
    return vk_cfg.ssid[0] && vk_cfg.server[0] && vk_cfg.token[0];
}
