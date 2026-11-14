// Characters to HID key codes for a US keyboard layout on the computer.
//
// A Bluetooth keyboard sends keys, not characters, so only what a US
// keyboard can type is typed. Typographic quotes and dashes (common in
// Whisper output) and accented Latin letters become their plain forms.
#include <string.h>
#include "vk.h"

#define SHIFT 0x02

enum {
    KEY_ENTER = 0x28, KEY_ESC = 0x29, KEY_BACKSPACE = 0x2A, KEY_TAB = 0x2B, KEY_SPACE = 0x2C,
    KEY_RIGHT = 0x4F, KEY_LEFT = 0x50, KEY_DOWN = 0x51, KEY_UP = 0x52,
};

// Printable ASCII 0x20–0x7E: key code, with bit 7 set for Shift.
static const uint8_t ascii[95] = {
    0x2C, 0x9E, 0xB4, 0xA0, 0xA1, 0xA2, 0xA4, 0x34,  //   ! " # $ % & '
    0xA6, 0xA7, 0xA5, 0xAE, 0x36, 0x2D, 0x37, 0x38,  // ( ) * + , - . /
    0x27, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,  // 0 1 2 3 4 5 6 7
    0x25, 0x26, 0xB3, 0x33, 0xB6, 0x2E, 0xB7, 0xB8,  // 8 9 : ; < = > ?
    0x9F, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,  // @ A B C D E F G
    0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,  // H I J K L M N O
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,  // P Q R S T U V W
    0x9B, 0x9C, 0x9D, 0x2F, 0x31, 0x30, 0xA3, 0xAD,  // X Y Z [ \ ] ^ _
    0x35, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,  // ` a b c d e f g
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,  // h i j k l m n o
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,  // p q r s t u v w
    0x1B, 0x1C, 0x1D, 0xAF, 0xB1, 0xB0, 0xB5,        // x y z { | } ~
};

// Latin-1 letters U+00C0–U+00FF without their accents ('\0': no plain form).
static const char latin1[65] = "AAAAAAACEEEEIIIIDNOOOOOxOUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty";

static int ascii_stroke(char c, vk_stroke_t *out)
{
    if (c == '\n') {
        *out = (vk_stroke_t){0, KEY_ENTER};
        return 1;
    }
    if (c == '\t') {
        *out = (vk_stroke_t){0, KEY_TAB};
        return 1;
    }
    if (c < 0x20 || c > 0x7E) {
        return 0;
    }
    uint8_t k = ascii[c - 0x20];
    *out = (vk_stroke_t){k & 0x80 ? SHIFT : 0, k & 0x7F};
    return 1;
}

int keymap_lookup(uint32_t cp, vk_stroke_t out[3])
{
    const char *plain = NULL;
    if (cp < 0x80) {
        return ascii_stroke((char)cp, out);
    }
    switch (cp) {
    case 0x00A0: case 0x2002: case 0x2003: case 0x2009: case 0x202F:
        plain = " "; break;   // non-breaking and thin spaces
    case 0x2018: case 0x2019: case 0x201A: case 0x2032:
        plain = "'"; break;
    case 0x201C: case 0x201D: case 0x201E: case 0x2033:
        plain = "\""; break;
    case 0x2010: case 0x2011: case 0x2012: case 0x2013: case 0x2014: case 0x2212:
        plain = "-"; break;
    case 0x2026:
        plain = "..."; break;
    case 0x00D7:
        plain = "x"; break;
    case 0x00DF:
        plain = "ss"; break;
    case 0x0152: plain = "OE"; break;
    case 0x0153: plain = "oe"; break;
    case 0x00C6: plain = "AE"; break;
    case 0x00E6: plain = "ae"; break;
    }
    if (!plain && cp >= 0x00C0 && cp <= 0x00FF && latin1[cp - 0x00C0] != 'x') {
        static char one[2];
        one[0] = latin1[cp - 0x00C0];
        plain = one;
    }
    if (!plain) {
        return 0;
    }
    int n = 0;
    for (const char *p = plain; *p && n < 3; p++) {
        n += ascii_stroke(*p, &out[n]);
    }
    return n;
}

int keymap_named(const char *name)
{
    static const struct {
        const char *name;
        int code;
    } keys[] = {
        {"backspace", KEY_BACKSPACE}, {"enter", KEY_ENTER}, {"up", KEY_UP}, {"down", KEY_DOWN},
        {"left", KEY_LEFT}, {"right", KEY_RIGHT}, {"space", KEY_SPACE}, {"tab", KEY_TAB}, {"escape", KEY_ESC},
        // F1–F12 are the HID usages 0x3A–0x45
        {"f1", 0x3A}, {"f2", 0x3B}, {"f3", 0x3C}, {"f4", 0x3D}, {"f5", 0x3E}, {"f6", 0x3F},
        {"f7", 0x40}, {"f8", 0x41}, {"f9", 0x42}, {"f10", 0x43}, {"f11", 0x44}, {"f12", 0x45},
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        if (strcmp(name, keys[i].name) == 0) {
            return keys[i].code;
        }
    }
    return -1;
}
