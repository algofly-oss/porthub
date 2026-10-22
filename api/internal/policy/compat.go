// Package policy is the private-network policy model (shared/access_policy.py)
// and private overlay logic (shared/private_overlay.py). Validation mirrors
// pydantic v1: same coercions, normalised values, error order and texts.
package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/algofly-oss/porthub/api/internal/validation"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// ErrorItem is one pydantic v1 error as FastAPI renders it.
type ErrorItem struct {
	Loc  []any          `json:"loc"`
	Msg  string         `json:"msg"`
	Type string         `json:"type"`
	Ctx  map[string]any `json:"ctx,omitempty"`
}

// ValidationError is a pydantic ValidationError.
type ValidationError struct{ Items []ErrorItem }

func (e *ValidationError) Error() string {
	parts := []string{}
	for _, item := range e.Items {
		parts = append(parts, fmt.Sprint(item.Loc, ": ", item.Msg))
	}
	return strings.Join(parts, "; ")
}

// errs collects errors with a location prefix.
type errs struct{ items []ErrorItem }

func (e *errs) add(loc []any, msg, typ string, ctx map[string]any) {
	e.items = append(e.items, ErrorItem{Loc: append([]any{}, loc...), Msg: msg, Type: typ, Ctx: ctx})
}

func (e *errs) valueError(loc []any, msg string) { e.add(loc, msg, "value_error", nil) }

func (e *errs) err() error {
	if len(e.items) == 0 {
		return nil
	}
	return &ValidationError{Items: e.items}
}

func at(loc []any, more ...any) []any { return append(append([]any{}, loc...), more...) }

// Prefix returns err's items with loc prefixed (e.g. "body").
func Prefix(err error, loc ...any) []ErrorItem {
	v, ok := err.(*ValidationError)
	if !ok {
		return nil
	}
	out := make([]ErrorItem, len(v.Items))
	for i, item := range v.Items {
		item.Loc = append(append([]any{}, loc...), item.Loc...)
		out[i] = item
	}
	return out
}

func missing(e *errs, loc []any) { e.add(loc, "field required", "value_error.missing", nil) }

func noneNotAllowed(e *errs, loc []any) {
	e.add(loc, "none is not an allowed value", "type_error.none.not_allowed", nil)
}

// AsDict mirrors passing a value where a pydantic model or dict is expected.
func AsDict(v any) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return x, true
	case *validation.Object:
		return x.Values, true
	case bson.M:
		return x, true
	case bson.D:
		m := map[string]any{}
		for _, e := range x {
			m[e.Key] = e.Value
		}
		return m, true
	}
	return nil, false
}

func asList(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case bson.A:
		return x, true
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// number kinds as Python sees them.
func pyNumber(v any) (i *big.Int, f float64, isInt, isFloat bool) {
	switch x := v.(type) {
	case json.Number:
		s := x.String()
		if !strings.ContainsAny(s, ".eE") {
			b, ok := new(big.Int).SetString(s, 10)
			if ok {
				return b, 0, true, false
			}
		}
		fv, err := strconv.ParseFloat(s, 64)
		if err != nil { // out of range parses as +-Inf like Python
			fv = math.Inf(1)
			if strings.HasPrefix(s, "-") {
				fv = math.Inf(-1)
			}
		}
		return nil, fv, false, true
	case int:
		return big.NewInt(int64(x)), 0, true, false
	case int32:
		return big.NewInt(int64(x)), 0, true, false
	case int64:
		return big.NewInt(x), 0, true, false
	case float64:
		return nil, x, false, true
	case float32:
		return nil, float64(x), false, true
	}
	return nil, 0, false, false
}

// PyFloat mirrors repr(float).
func PyFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expS, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := fmt.Sprintf("%+03d", exp)
		return sign + m + "e" + es
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + digits
	}
	if len(digits) <= exp+1 {
		return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
	}
	return sign + digits[:exp+1] + "." + digits[exp+1:]
}

// PyStr mirrors str(value) for the values Mongo and JSON produce.
func PyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case bson.ObjectID:
		return x.Hex()
	case bson.DateTime:
		return pyDateTime(x)
	}
	if i, f, isInt, isFloat := pyNumber(v); isInt {
		return i.String()
	} else if isFloat {
		return PyFloat(f)
	}
	return fmt.Sprint(v)
}

func pyDateTime(d bson.DateTime) string {
	t := d.Time().UTC()
	s := t.Format("2006-01-02 15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

// pydantic str_validator: str, or str() of int/float (bool included).
func coerceStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return PyStr(x), true
	}
	if _, _, isInt, isFloat := pyNumber(v); isInt || isFloat {
		return PyStr(v), true
	}
	return "", false
}

// strField validates a (constrained) str field. ok=false means an error was recorded.
func strField(e *errs, loc []any, v any, minLen, maxLen int) (string, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return "", false
	}
	s, ok := coerceStr(v)
	if !ok {
		e.add(loc, "str type expected", "type_error.str", nil)
		return "", false
	}
	n := utf8.RuneCountInString(s)
	if minLen > 0 && n < minLen {
		e.add(loc, fmt.Sprintf("ensure this value has at least %d characters", minLen), "value_error.any_str.min_length", map[string]any{"limit_value": minLen})
		return "", false
	}
	if maxLen > 0 && n > maxLen {
		e.add(loc, fmt.Sprintf("ensure this value has at most %d characters", maxLen), "value_error.any_str.max_length", map[string]any{"limit_value": maxLen})
		return "", false
	}
	return s, true
}

var boolFalse = map[string]bool{"0": true, "off": true, "f": true, "false": true, "n": true, "no": true}
var boolTrue = map[string]bool{"1": true, "on": true, "t": true, "true": true, "y": true, "yes": true}

func boolField(e *errs, loc []any, v any) (bool, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return false, false
	}
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		l := PyLower(x)
		if boolFalse[l] {
			return false, true
		}
		if boolTrue[l] {
			return true, true
		}
	default:
		if i, f, isInt, isFloat := pyNumber(v); isInt && i.IsInt64() && (i.Int64() == 0 || i.Int64() == 1) {
			return i.Int64() == 1, true
		} else if isFloat && (f == 0 || f == 1) {
			return f == 1, true
		}
	}
	e.add(loc, "value could not be parsed to a boolean", "type_error.bool", nil)
	return false, false
}

// pyIntString mirrors int(str): whitespace, sign, Unicode digits, single underscores.
func pyIntString(s string) (*big.Int, bool) {
	s = PyStrip(s)
	neg := false
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return nil, false
	}
	var b strings.Builder
	prevUnderscore := true
	for _, r := range s {
		if r == '_' {
			if prevUnderscore {
				return nil, false
			}
			prevUnderscore = true
			continue
		}
		d, ok := digitValue(r)
		if !ok {
			return nil, false
		}
		b.WriteByte(byte('0' + d))
		prevUnderscore = false
	}
	if prevUnderscore {
		return nil, false
	}
	i, _ := new(big.Int).SetString(b.String(), 10)
	if neg {
		i.Neg(i)
	}
	return i, true
}

// digitValue is the value of a Unicode decimal digit (category Nd), which
// always come in contiguous runs starting at zero.
func digitValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if !unicode.IsDigit(r) {
		return 0, false
	}
	k := 0
	for unicode.IsDigit(r - rune(k) - 1) {
		k++
	}
	return k % 10, true
}

// intField mirrors pydantic int_validator plus ge/le constraints.
func intField(e *errs, loc []any, v any, ge, le *int64) (int64, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return 0, false
	}
	var value *big.Int
	switch x := v.(type) {
	case bool:
		value = big.NewInt(0)
		if x {
			value = big.NewInt(1)
		}
	case string:
		if utf8.RuneCountInString(x) <= 4300 {
			value, _ = pyIntString(x)
		}
	default:
		if i, f, isInt, isFloat := pyNumber(v); isInt {
			value = i
		} else if isFloat && !math.IsInf(f, 0) && !math.IsNaN(f) {
			value, _ = new(big.Float).SetFloat64(math.Trunc(f)).Int(nil)
		}
	}
	if value == nil || !value.IsInt64() {
		e.add(loc, "value is not a valid integer", "type_error.integer", nil)
		return 0, false
	}
	n := value.Int64()
	if ge != nil && n < *ge {
		e.add(loc, fmt.Sprintf("ensure this value is greater than or equal to %d", *ge), "value_error.number.not_ge", map[string]any{"limit_value": *ge})
		return 0, false
	}
	if le != nil && n > *le {
		e.add(loc, fmt.Sprintf("ensure this value is less than or equal to %d", *le), "value_error.number.not_le", map[string]any{"limit_value": *le})
		return 0, false
	}
	return n, true
}

func i64(v int64) *int64 { return &v }

// literalField mirrors typing.Literal of strings.
func literalField(e *errs, loc []any, v any, permitted ...string) (string, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return "", false
	}
	if s, ok := v.(string); ok {
		for _, p := range permitted {
			if s == p {
				return s, true
			}
		}
	}
	quoted := make([]string, len(permitted))
	list := make([]any, len(permitted))
	for i, p := range permitted {
		quoted[i] = "'" + p + "'"
		list[i] = p
	}
	e.add(loc, "unexpected value; permitted: "+strings.Join(quoted, ", "), "value_error.const", map[string]any{"given": jsonValue(v), "permitted": list})
	return "", false
}

// jsonValue converts Mongo values for a JSON error context.
func jsonValue(v any) any {
	switch x := v.(type) {
	case *validation.Object:
		return jsonValue(x.Values)
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			out[k] = jsonValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = jsonValue(val)
		}
		return out
	case bson.ObjectID:
		return x.Hex()
	case bson.M:
		out := map[string]any{}
		for k, val := range x {
			out[k] = jsonValue(val)
		}
		return out
	case bson.A:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = jsonValue(val)
		}
		return out
	}
	return v
}

// listField mirrors a list with optional min/max items: the length check
// precedes item validation. ok=false means an error was recorded.
func listField(e *errs, loc []any, v any, minItems, maxItems int) ([]any, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return nil, false
	}
	list, ok := asList(v)
	if !ok {
		e.add(loc, "value is not a valid list", "type_error.list", nil)
		return nil, false
	}
	if minItems > 0 && len(list) < minItems {
		e.add(loc, fmt.Sprintf("ensure this value has at least %d items", minItems), "value_error.list.min_items", map[string]any{"limit_value": minItems})
		return nil, false
	}
	if maxItems > 0 && len(list) > maxItems {
		e.add(loc, fmt.Sprintf("ensure this value has at most %d items", maxItems), "value_error.list.max_items", map[string]any{"limit_value": maxItems})
		return nil, false
	}
	return list, true
}

func dictField(e *errs, loc []any, v any) (map[string]any, bool) {
	if v == nil {
		noneNotAllowed(e, loc)
		return nil, false
	}
	d, ok := AsDict(v)
	if !ok {
		d, ok = pairsDict(v)
	}
	if !ok {
		e.add(loc, "value is not a valid dict", "type_error.dict", nil)
	}
	return d, ok
}

// pairsDict mirrors dict(value) for a list of [key, value] pairs.
func pairsDict(v any) (map[string]any, bool) {
	list, ok := asList(v)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for _, item := range list {
		switch x := item.(type) {
		case string:
			r := []rune(x)
			if len(r) != 2 {
				return nil, false
			}
			out[string(r[0])] = string(r[1])
		default:
			pair, ok := asList(item)
			if !ok || len(pair) != 2 {
				return nil, false
			}
			key, ok := pair[0].(string)
			if !ok {
				return nil, false
			}
			out[key] = pair[1]
		}
	}
	return out, true
}

// IsPySpace mirrors str.isspace for one character.
func IsPySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// PyStrip mirrors str.strip().
func PyStrip(s string) string { return strings.TrimFunc(s, IsPySpace) }

// PyLower mirrors str.lower() (including the one multi-character mapping).
func PyLower(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇"))
}

// Python truthiness of a Mongo/JSON value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case bson.A:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case bson.M:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case bson.D:
		return len(x) > 0
	}
	if i, f, isInt, isFloat := pyNumber(v); isInt {
		return i.Sign() != 0
	} else if isFloat {
		return f != 0
	}
	return true
}

// Key gives a map key that distinguishes Python values of different types
// (ObjectId("..") != "..").
func Key(v any) string {
	switch x := v.(type) {
	case bson.ObjectID:
		return "o:" + x.Hex()
	case string:
		return "s:" + x
	case nil:
		return "n:"
	}
	if i, f, isInt, isFloat := pyNumber(v); isInt {
		return "i:" + i.String()
	} else if isFloat {
		if f == math.Trunc(f) && !math.IsInf(f, 0) {
			b, _ := new(big.Float).SetFloat64(f).Int(nil)
			return "i:" + b.String()
		}
		return "f:" + PyFloat(f)
	}
	return fmt.Sprintf("%T:%v", v, v)
}

// Equal mirrors == for ids and scalars.
func Equal(a, b any) bool { return Key(a) == Key(b) }

// MissingBody is FastAPI's error for an empty or null required body.
func MissingBody() []ErrorItem {
	return []ErrorItem{{Loc: []any{"body"}, Msg: "field required", Type: "value_error.missing"}}
}
