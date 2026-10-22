package policy

import (
	"regexp"
	"sort"
	"strings"

	"github.com/algofly-oss/porthub/api/internal/validation"
)

// Request bodies of router/access (pydantic models defined in the routers).

type DeleteBook struct{ Revision int64 }

func ParseDeleteBook(raw any) (DeleteBook, error) {
	e := &errs{}
	var out DeleteBook
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d["revision"]; !has {
			missing(e, []any{"revision"})
		} else {
			out.Revision, _ = intField(e, []any{"revision"}, v, i64(1), nil)
		}
	}
	return out, e.err()
}

func strList(e *errs, loc []any, v any, maxItems int) []string {
	list, ok := listField(e, loc, v, 0, maxItems)
	if !ok {
		return []string{}
	}
	out := []string{}
	for i, item := range list {
		if s, ok := strField(e, at(loc, i), item, 0, 0); ok {
			out = append(out, s)
		}
	}
	return out
}

type GroupMembers struct{ MachineIDs, UserIDs []string }

func ParseGroupMembers(raw any) (GroupMembers, error) {
	e := &errs{}
	out := GroupMembers{MachineIDs: []string{}, UserIDs: []string{}}
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d["machine_ids"]; has {
			out.MachineIDs = strList(e, []any{"machine_ids"}, v, 1000)
		}
		if v, has := d["user_ids"]; has {
			out.UserIDs = strList(e, []any{"user_ids"}, v, 1000)
		}
	}
	return out, e.err()
}

type ConnectionTest struct {
	SourceID, DestinationID, Protocol string
	Port                              int
}

func ParseConnectionTest(raw any) (ConnectionTest, error) {
	e := &errs{}
	out := ConnectionTest{Protocol: "tcp", Port: 443}
	if d, ok := dictField(e, nil, raw); ok {
		for _, f := range []struct {
			key string
			dst *string
		}{{"source_id", &out.SourceID}, {"destination_id", &out.DestinationID}} {
			if v, has := d[f.key]; !has {
				missing(e, []any{f.key})
			} else {
				*f.dst, _ = strField(e, []any{f.key}, v, 0, 0)
			}
		}
		if v, has := d["protocol"]; has {
			out.Protocol, _ = literalField(e, []any{"protocol"}, v, "tcp", "udp", "icmp")
		}
		if v, has := d["port"]; has {
			port, _ := intField(e, []any{"port"}, v, i64(1), i64(65535))
			out.Port = int(port)
		}
	}
	return out, e.err()
}

type Invite struct{ Email, Role string }

func ParseInvite(raw any) (Invite, error) {
	e := &errs{}
	out := Invite{Role: "member"}
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d["email"]; !has {
			missing(e, []any{"email"})
		} else if s, ok := strField(e, []any{"email"}, v, 3, 254); ok {
			s = PyLower(PyStrip(s))
			parts := strings.Split(s, "@")
			if strings.Count(s, "@") != 1 || strings.IndexFunc(s, IsPySpace) >= 0 || !strings.Contains(parts[len(parts)-1], ".") {
				e.valueError([]any{"email"}, "Enter a valid email address")
			}
			out.Email = s
		}
		if v, has := d["role"]; has {
			out.Role, _ = literalField(e, []any{"role"}, v, "admin", "member")
		}
	}
	return out, e.err()
}

// ParseToken validates {key: str(min_length=32, max_length=200)}
// (InvitationToken.token, Bootstrap.ticket).
func ParseToken(raw any, key string) (string, error) {
	e := &errs{}
	out := ""
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d[key]; !has {
			missing(e, []any{key})
		} else {
			out, _ = strField(e, []any{key}, v, 32, 200)
		}
	}
	return out, e.err()
}

// optionalHostname mirrors Optional[str] max_length=48 with custom_hostname.
func optionalHostname(e *errs, d map[string]any, key string) *string {
	v, has := d[key]
	if !has || v == nil {
		return nil
	}
	s, ok := strField(e, []any{key}, v, 0, 48)
	if !ok {
		return nil
	}
	if PyStrip(s) == "" {
		return nil
	}
	s = strings.TrimRight(PyLower(PyStrip(s)), ".")
	if !Hostname.MatchString(s) {
		e.valueError([]any{key}, "Use up to 48 letters, numbers or hyphens, not starting or ending with a hyphen")
		return nil
	}
	return &s
}

type PeerEnrollment struct {
	MachineID       string
	Hostname, Alias *string
}

func ParsePeerEnrollment(raw any) (PeerEnrollment, error) {
	e := &errs{}
	var out PeerEnrollment
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d["machine_id"]; !has {
			missing(e, []any{"machine_id"})
		} else {
			out.MachineID, _ = strField(e, []any{"machine_id"}, v, 0, 0)
		}
		out.Hostname = optionalHostname(e, d, "hostname")
		out.Alias = optionalHostname(e, d, "alias")
	}
	return out, e.err()
}

func ParseHostnameChange(raw any) (*string, error) {
	e := &errs{}
	var out *string
	if d, ok := dictField(e, nil, raw); ok {
		out = optionalHostname(e, d, "hostname")
	}
	return out, e.err()
}

func ParsePeerChange(raw any) (bool, error) {
	e := &errs{}
	out := false
	if d, ok := dictField(e, nil, raw); ok {
		if v, has := d["enabled"]; !has {
			missing(e, []any{"enabled"})
		} else {
			out, _ = boolField(e, []any{"enabled"}, v)
		}
	}
	return out, e.err()
}

const sessionPattern = `^[a-zA-Z0-9-]{16,64}$`

// Python's re.match with "$" also accepts one trailing newline.
var sessionRE = regexp.MustCompile(`^[a-zA-Z0-9-]{16,64}\n?$`)

func regexField(e *errs, loc []any, v any) (string, bool) {
	s, ok := strField(e, loc, v, 0, 0)
	if !ok {
		return "", false
	}
	if !sessionRE.MatchString(s) {
		e.add(loc, `string does not match regex "`+sessionPattern+`"`, "value_error.str.regex", map[string]any{"pattern": sessionPattern})
		return "", false
	}
	return s, true
}

type Description struct{ Type, SDP string }

func (d Description) Dict() map[string]any { return map[string]any{"type": d.Type, "sdp": d.SDP} }

type Signal struct {
	To, Session string
	Description Description
}

type ClientSync struct {
	PeerID, Token, Fingerprint, Instance string
	Signals                              []Signal
	Acks                                 []string
	Paths                                map[string]string
}

func signalModel(e *errs, loc []any, v any) (Signal, bool) {
	d, ok := dictField(e, loc, v)
	if !ok {
		return Signal{}, false
	}
	n := len(e.items)
	var s Signal
	if raw, has := d["to"]; !has {
		missing(e, at(loc, "to"))
	} else {
		s.To, _ = strField(e, at(loc, "to"), raw, 1, 60)
	}
	if raw, has := d["session"]; !has {
		missing(e, at(loc, "session"))
	} else {
		s.Session, _ = regexField(e, at(loc, "session"), raw)
	}
	if raw, has := d["description"]; !has {
		missing(e, at(loc, "description"))
	} else if dd, ok := dictField(e, at(loc, "description"), raw); ok {
		dl := at(loc, "description")
		if t, has := dd["type"]; !has {
			missing(e, at(dl, "type"))
		} else {
			s.Description.Type, _ = literalField(e, at(dl, "type"), t, "offer", "answer")
		}
		if sdp, has := dd["sdp"]; !has {
			missing(e, at(dl, "sdp"))
		} else {
			s.Description.SDP, _ = strField(e, at(dl, "sdp"), sdp, 1, 65536)
		}
	}
	return s, len(e.items) == n
}

func ParseClientSync(raw any) (ClientSync, error) {
	e := &errs{}
	out := ClientSync{Signals: []Signal{}, Acks: []string{}, Paths: map[string]string{}}
	d, ok := dictField(e, nil, raw)
	if !ok {
		return out, e.err()
	}
	if v, has := d["peer_id"]; !has {
		missing(e, []any{"peer_id"})
	} else {
		out.PeerID, _ = strField(e, []any{"peer_id"}, v, 0, 60)
	}
	if v, has := d["token"]; !has {
		missing(e, []any{"token"})
	} else {
		out.Token, _ = strField(e, []any{"token"}, v, 32, 200)
	}
	if v, has := d["fingerprint"]; !has {
		missing(e, []any{"fingerprint"})
	} else if s, ok := strField(e, []any{"fingerprint"}, v, 95, 95); ok {
		if !Fingerprint.MatchString(s) {
			e.valueError([]any{"fingerprint"}, "A SHA-256 certificate fingerprint is required")
		}
		out.Fingerprint = strings.ToUpper(s)
	}
	if v, has := d["instance"]; !has {
		missing(e, []any{"instance"})
	} else {
		out.Instance, _ = regexField(e, []any{"instance"}, v)
	}
	if v, has := d["signals"]; has {
		if list, ok := listField(e, []any{"signals"}, v, 0, 16); ok {
			for i, item := range list {
				if s, ok := signalModel(e, []any{"signals", i}, item); ok {
					out.Signals = append(out.Signals, s)
				}
			}
		}
	}
	if v, has := d["acks"]; has {
		out.Acks = strList(e, []any{"acks"}, v, 128)
	}
	if v, has := d["paths"]; has {
		if paths, ok := dictField(e, []any{"paths"}, v); ok {
			var keys []string
			if o, ok := v.(*validation.Object); ok {
				keys = o.Keys // body order, like a Python dict
			} else {
				for k := range paths {
					keys = append(keys, k)
				}
				sort.Strings(keys)
			}
			for _, k := range keys {
				if s, ok := literalField(e, []any{"paths", k}, paths[k], "direct", "relay", "connecting"); ok {
					out.Paths[k] = s
				}
			}
		}
	}
	return out, e.err()
}
