package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// pyIntString parses like Python int(str): surrounding whitespace, a sign,
// digits with single underscores between them. overflow reports a valid
// integer that does not fit in int64 (n is then clamped to its sign).
func pyIntString(s string) (n int64, ok, overflow bool) {
	s = strings.TrimSpace(s)
	body := strings.TrimLeft(s, "+-")
	if len(s)-len(body) > 1 || body == "" || body[0] == '_' || body[len(body)-1] == '_' || strings.Contains(body, "__") {
		return 0, false, false
	}
	for _, c := range body {
		if c != '_' && (c < '0' || c > '9') {
			return 0, false, false
		}
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 10, 64)
	return n, true, err != nil
}

// pyInt mirrors int(value) on a decoded JSON value (json.Number numbers):
// floats truncate, bools are 0/1, strings parse; anything else fails.
func pyInt(v any) (int64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
		f, err := x.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) >= 1<<63 {
			return 0, false
		}
		return int64(f), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) >= 1<<63 {
			return 0, false
		}
		return int64(x), true
	case string:
		n, ok, overflow := pyIntString(x)
		return n, ok && !overflow
	}
	return 0, false
}

// pyNumber mirrors isinstance(v, (int, float)) followed by int(v).
func pyNumber(v any) (int64, bool) {
	switch v.(type) {
	case bool, json.Number, float64, int, int64:
		return pyInt(v)
	}
	return 0, false
}

// pyFloat marshals like Python's float repr (1.0, 2.5, 1e-05).
type pyFloat float64

func (f pyFloat) MarshalJSON() ([]byte, error) { return []byte(formatPyFloat(float64(f))), nil }

func formatPyFloat(f float64) string {
	abs := math.Abs(f)
	if abs != 0 && (abs < 1e-4 || abs >= 1e16) {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		return s
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// pyDumps renders a string list like json.dumps (", " separator, ASCII only),
// the format stored in SQLite by the Python service.
func pyDumps(items []string) string {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pyQuote(s))
	}
	b.WriteByte(']')
	return b.String()
}

func pyQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || (r > 0x7f && r < 0x10000):
			fmt.Fprintf(&b, `\u%04x`, r)
		case r >= 0x10000:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
