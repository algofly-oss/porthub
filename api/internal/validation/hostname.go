package validation

import "strings"

// ValidHostname mirrors HOSTNAME_RE.fullmatch (re.IGNORECASE):
// 1-253 characters of dot-separated labels, 1-63 of [A-Za-z0-9-] each, not
// starting or ending with "-". Python's case-insensitive class also matches
// U+0130, U+0131, U+017F and U+212A.
func ValidHostname(s string) bool {
	n := len([]rune(s))
	if n < 1 || n > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		r := []rune(label)
		if len(r) < 1 || len(r) > 63 || r[0] == '-' || r[len(r)-1] == '-' {
			return false
		}
		for _, c := range r {
			if !hostnameChar(c) {
				return false
			}
		}
	}
	return true
}

func hostnameChar(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		return true
	case c == 0x130, c == 0x131, c == 0x17f, c == 0x212a:
		return true
	}
	return false
}
