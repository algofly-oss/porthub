// Package validation validates JSON request bodies the way the Python API's
// pydantic v1 models did (FastAPI 0.79): the same coercions (5 -> "5",
// "22" -> 22, "yes" -> true), the same accept/reject decisions and the same
// 422 {"detail": [{"loc", "msg", "type", "ctx"}]} items.
package validation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/algofly-oss/porthub/api/internal/httpapi"
)

// Object is a JSON object that keeps key order (Python dicts do).
type Object struct {
	Keys   []string
	Values map[string]any
}

func (o *Object) Get(key string) (any, bool) {
	v, ok := o.Values[key]
	return v, ok
}

// Decode parses JSON like json.loads: objects -> *Object, arrays -> []any,
// numbers -> json.Number, duplicate keys keep the last value.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("Extra data")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &Object{Values: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := kt.(string)
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, seen := o.Values[key]; !seen {
					o.Keys = append(o.Keys, key)
				}
				o.Values[key] = v
			}
			_, err := dec.Token()
			return o, err
		case '[':
			list := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return list, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	}
	return tok, nil
}

// Body is embedded (json:"-") in documented request body structs: it keeps
// the raw JSON so validation follows pydantic instead of the Go types.
type Body struct {
	value any
	err   error
}

func (b *Body) UnmarshalJSON(data []byte) error {
	b.value, b.err = Decode(data)
	return nil
}

// Bodied is any request body struct embedding Body.
type Bodied interface{ raw() *Body }

func (b *Body) raw() *Body { return b }

// Item is one FastAPI validation error.
type Item struct {
	Loc  []any          `json:"loc"`
	Msg  string         `json:"msg"`
	Type string         `json:"type"`
	Ctx  map[string]any `json:"ctx,omitempty"`
}

// Model collects field values and errors in pydantic's field order.
type Model struct {
	obj  *Object
	errs []Item
}

// Load starts validating a request body (nil when no body was sent).
func Load(b Bodied) (*Model, error) {
	if b == nil || reflect.ValueOf(b).IsNil() || (b.raw().value == nil && b.raw().err == nil) {
		return nil, Fail(Item{Loc: []any{"body"}, Msg: "field required", Type: "value_error.missing"})
	}
	r := b.raw()
	if r.err != nil {
		return nil, Fail(Item{Loc: []any{"body", 0}, Msg: r.err.Error(), Type: "value_error.jsondecode"})
	}
	obj, ok := r.value.(*Object)
	if !ok {
		return nil, Fail(Item{Loc: []any{"body"}, Msg: "value is not a valid dict", Type: "type_error.dict"})
	}
	return &Model{obj: obj}, nil
}

// FromObject validates an already decoded object (tests).
func FromObject(o *Object) *Model { return &Model{obj: o} }

// Fail returns a 422 FastAPI validation error.
func Fail(items ...Item) error {
	return &httpapi.FastAPIError{Status: 422, Detail: items}
}

// Err is the collected 422 error, or nil when every field was valid.
func (m *Model) Err() error {
	if len(m.errs) == 0 {
		return nil
	}
	return Fail(m.errs...)
}

func (m *Model) Errors() []Item { return m.errs }
func (m *Model) OK() bool       { return len(m.errs) == 0 }

// Add records an error at body.<loc...>.
func (m *Model) Add(msg, typ string, ctx map[string]any, loc ...any) {
	m.errs = append(m.errs, Item{Loc: append([]any{"body"}, loc...), Msg: msg, Type: typ, Ctx: ctx})
}

// Value returns the first present key (alias first, then field name).
func (m *Model) Value(keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m.obj.Get(k); ok {
			return v, true
		}
	}
	return nil, false
}

func (m *Model) missing(loc string) { m.Add("field required", "value_error.missing", nil, loc) }
func (m *Model) none(loc ...any) {
	m.Add("none is not an allowed value", "type_error.none.not_allowed", nil, loc...)
}

// ReqStr is a required str field; ok is false after an error.
func (m *Model) ReqStr(keys ...string) (string, bool) {
	v, present := m.Value(keys...)
	if !present {
		m.missing(keys[0])
		return "", false
	}
	return m.str(v, keys[0])
}

func (m *Model) str(v any, loc ...any) (string, bool) {
	if v == nil {
		m.none(loc...)
		return "", false
	}
	s, ok := Str(v)
	if !ok {
		m.Add("str type expected", "type_error.str", nil, loc...)
	}
	return s, ok
}

// DefStr is a str field with a default (null is rejected).
func (m *Model) DefStr(def string, keys ...string) (string, bool) {
	v, present := m.Value(keys...)
	if !present {
		return def, true
	}
	return m.str(v, keys[0])
}

// OptStr is an Optional[str] field: nil for null.
func (m *Model) OptStr(def *string, keys ...string) (*string, bool) {
	v, present := m.Value(keys...)
	if !present {
		return def, true
	}
	if v == nil {
		return nil, true
	}
	s, ok := m.str(v, keys[0])
	return &s, ok
}

// MinLen / MaxLen are constr length checks (characters).
func (m *Model) MinLen(s string, n int, loc string) bool {
	if len([]rune(s)) < n {
		m.Add(fmt.Sprintf("ensure this value has at least %d characters", n), "value_error.any_str.min_length", map[string]any{"limit_value": n}, loc)
		return false
	}
	return true
}

func (m *Model) MaxLen(s string, n int, loc string) bool {
	if len([]rune(s)) > n {
		m.Add(fmt.Sprintf("ensure this value has at most %d characters", n), "value_error.any_str.max_length", map[string]any{"limit_value": n}, loc)
		return false
	}
	return true
}

func (m *Model) intRange(v any, ge, le int, loc string) (int, bool) {
	n, ok := Int(v)
	if !ok {
		m.Add("value is not a valid integer", "type_error.integer", nil, loc)
		return 0, false
	}
	if n.Cmp(big.NewInt(int64(ge))) < 0 {
		m.Add(fmt.Sprintf("ensure this value is greater than or equal to %d", ge), "value_error.number.not_ge", map[string]any{"limit_value": ge}, loc)
		return 0, false
	}
	if n.Cmp(big.NewInt(int64(le))) > 0 {
		m.Add(fmt.Sprintf("ensure this value is less than or equal to %d", le), "value_error.number.not_le", map[string]any{"limit_value": le}, loc)
		return 0, false
	}
	return int(n.Int64()), true
}

// ReqInt is a required conint(ge, le) field.
func (m *Model) ReqInt(ge, le int, keys ...string) (int, bool) {
	v, present := m.Value(keys...)
	if !present {
		m.missing(keys[0])
		return 0, false
	}
	if v == nil {
		m.none(keys[0])
		return 0, false
	}
	return m.intRange(v, ge, le, keys[0])
}

// OptInt is an Optional[conint(ge, le)] field defaulting to None.
func (m *Model) OptInt(ge, le int, keys ...string) (*int, bool) {
	v, present := m.Value(keys...)
	if !present || v == nil {
		return nil, true
	}
	n, ok := m.intRange(v, ge, le, keys[0])
	return &n, ok
}

// OptBool is an Optional[bool] field: nil for null.
func (m *Model) OptBool(def bool, keys ...string) (*bool, bool) {
	v, present := m.Value(keys...)
	if !present {
		return &def, true
	}
	if v == nil {
		return nil, true
	}
	b, ok := m.boolean(v, keys[0])
	return &b, ok
}

// DefBool is a bool field with a default (null is rejected).
func (m *Model) DefBool(def bool, keys ...string) (bool, bool) {
	v, present := m.Value(keys...)
	if !present {
		return def, true
	}
	if v == nil {
		m.none(keys[0])
		return false, false
	}
	return m.boolean(v, keys[0])
}

func (m *Model) boolean(v any, loc string) (bool, bool) {
	b, ok := Bool(v)
	if !ok {
		m.Add("value could not be parsed to a boolean", "type_error.bool", nil, loc)
	}
	return b, ok
}

// List checks a List[...] field (default []); items are validated by the caller.
func (m *Model) List(keys ...string) ([]any, bool) {
	v, present := m.Value(keys...)
	if !present {
		return []any{}, true
	}
	if v == nil {
		m.none(keys[0])
		return nil, false
	}
	list, ok := v.([]any)
	if !ok {
		m.Add("value is not a valid list", "type_error.list", nil, keys[0])
	}
	return list, ok
}

// StrList validates List[str] items.
func (m *Model) StrList(keys ...string) ([]string, bool) {
	list, ok := m.List(keys...)
	if !ok {
		return nil, false
	}
	out := []string{}
	for i, item := range list {
		s, itemOK := m.str(item, keys[0], i)
		ok = ok && itemOK
		out = append(out, s)
	}
	return out, ok
}

// --- Python value semantics ---

// Str mirrors pydantic v1 str_validator: str as-is, int/float/bool via str().
func Str(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return NumberStr(x), true
	case bool:
		return PyStr(x), true
	}
	return "", false
}

// NumberStr mirrors str() of the int or float json.loads makes of a number.
func NumberStr(n json.Number) string {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		if i, ok := new(big.Int).SetString(s, 10); ok {
			return i.String()
		}
	}
	f, _ := strconv.ParseFloat(s, 64)
	return FloatRepr(f)
}

// FloatRepr mirrors Python's repr(float).
func FloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // -d.ddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	sign := ""
	if strings.HasPrefix(mant, "-") {
		sign, mant = "-", mant[1:]
	}
	digits := strings.Replace(mant, ".", "", 1)
	if exp < -4 || exp >= 16 {
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es, exp = "-", -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, out, es, exp)
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + digits
	}
	if len(digits) <= exp+1 {
		return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
	}
	return sign + digits[:exp+1] + "." + digits[exp+1:]
}

// Int mirrors pydantic v1 int_validator (int(v) for bools, floats, strings).
func Int(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewInt(1), true
		}
		return big.NewInt(0), true
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			return new(big.Int).SetString(s, 10)
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsInf(f, 0) {
			return nil, false
		}
		i, _ := big.NewFloat(math.Trunc(f)).Int(nil)
		return i, true
	case string:
		return pyIntString(x)
	}
	return nil, false
}

// pyIntString mirrors int(str): surrounding whitespace, a sign, digits with
// single underscores between them.
func pyIntString(s string) (*big.Int, bool) {
	s = Strip(s)
	if len(s) > 4300 {
		return nil, false
	}
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		if strings.HasPrefix(s[1:], "+") || strings.HasPrefix(s[1:], "-") {
			return nil, false
		}
	}
	body := strings.TrimLeft(s, "+-")
	if body == "" || strings.HasPrefix(body, "_") || strings.HasSuffix(body, "_") || strings.Contains(body, "__") {
		return nil, false
	}
	for _, r := range body {
		if r != '_' && (r < '0' || r > '9') {
			return nil, false
		}
	}
	return new(big.Int).SetString(strings.ReplaceAll(s, "_", ""), 10)
}

// Bool mirrors pydantic v1 bool_validator.
func Bool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err == nil && f == 1 {
			return true, true
		}
		if err == nil && f == 0 {
			return false, true
		}
	case string:
		switch strings.ToLower(x) {
		case "1", "on", "t", "true", "y", "yes":
			return true, true
		case "0", "off", "f", "false", "n", "no":
			return false, true
		}
	}
	return false, false
}

// Truthy mirrors bool(value) for decoded JSON values.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return err != nil || f != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case *Object:
		return len(x.Keys) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// PyStr mirrors str(value) for decoded JSON values.
func PyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return NumberStr(x)
	}
	return Repr(v)
}

// Repr mirrors repr(value) for decoded JSON values.
func Repr(v any) string {
	switch x := v.(type) {
	case string:
		return reprString(x)
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = Repr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *Object:
		parts := make([]string, len(x.Keys))
		for i, k := range x.Keys {
			parts[i] = reprString(k) + ": " + Repr(x.Values[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return PyStr(v)
}

func reprString(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// IsSpace mirrors str.isspace for one character.
func IsSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// Strip mirrors str.strip().
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Lower mirrors str.lower() (U+0130 lowers to "i" + combining dot).
func Lower(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇"))
}

// Iterate mirrors iterating a value in a pre-validator: lists, the
// characters of a string, the keys of an object; numbers raise TypeError.
func Iterate(v any) ([]any, string) {
	switch x := v.(type) {
	case []any:
		return x, ""
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, ""
	case *Object:
		out := make([]any, len(x.Keys))
		for i, k := range x.Keys {
			out[i] = k
		}
		return out, ""
	case bool:
		return nil, "'bool' object is not iterable"
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return nil, "'float' object is not iterable"
		}
		return nil, "'int' object is not iterable"
	}
	return nil, "'NoneType' object is not iterable"
}

// IPv4 mirrors ipaddress.IPv4Address(value) (strings and integers).
func IPv4(v any) (string, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return "0.0.0.1", true
		}
		return "0.0.0.0", true
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return "", false
		}
		n, ok := new(big.Int).SetString(string(x), 10)
		if !ok || n.Sign() < 0 || n.BitLen() > 32 {
			return "", false
		}
		u := n.Uint64()
		return fmt.Sprintf("%d.%d.%d.%d", u>>24, (u>>16)&255, (u>>8)&255, u&255), true
	case string:
		if ParseIPv4(x) {
			return x, true
		}
	}
	return "", false
}

// ParseIPv4 mirrors IPv4Address(str) acceptance (Python 3.10: four decimal
// octets, no leading zeros).
func ParseIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		if n, _ := strconv.Atoi(p); n > 255 {
			return false
		}
	}
	return true
}
