// Package access implements workspace administration and private peer control.
package access

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/policy"
	"github.com/algofly-oss/porthub/api/internal/validation"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type handlers struct{ app *core.App }
type output struct {
	CacheControl string `header:"Cache-Control"`
	Body         map[string]any
}

func reply(m map[string]any) *output { return &output{Body: m} }
func data(v any) *output             { return reply(map[string]any{"data": v}) }
func message(s string) *output       { return reply(map[string]any{"msg": s}) }

type requestBody struct {
	value any
	err   error
}

func (b *requestBody) UnmarshalJSON(raw []byte) error {
	b.value, b.err = validation.Decode(raw)
	return nil
}

type bodyInput struct{ Body *requestBody }
type pathBodyInput struct {
	ID   string `path:"id"`
	Body *requestBody
}
type pathInput struct {
	ID string `path:"id"`
}
type endpoint func(context.Context, string, any) (*output, error)

func validationError(err error) error {
	if err == nil {
		return nil
	}
	var v *policy.ValidationError
	if errors.As(err, &v) {
		return &httpapi.FastAPIError{Status: 422, Detail: policy.Prefix(err, "body")}
	}
	return err
}
func rawBody(b *requestBody) (any, error) {
	if b == nil || (b.value == nil && b.err == nil) {
		return nil, validation.Fail(validation.Item{Loc: []any{"body"}, Msg: "field required", Type: "value_error.missing"})
	}
	if b.err != nil {
		return nil, validation.Fail(validation.Item{Loc: []any{"body", 0}, Msg: b.err.Error(), Type: "value_error.jsondecode"})
	}
	return b.value, nil
}
func Register(api huma.API, app *core.App) {
	h := &handlers{app}
	register := func(id, method, path string, body bool, fn endpoint) {
		op := huma.Operation{OperationID: id, Method: method, Path: "/api/access" + path, Summary: strings.ReplaceAll(id, "-", " "), Tags: []string{"Private access control"}, DefaultStatus: 200, SkipValidateBody: true}
		finish := func(ctx context.Context, id string, raw any) (*output, error) {
			out, err := fn(ctx, id, raw)
			return out, validationError(err)
		}
		switch {
		case body && strings.Contains(path, "{id}"):
			huma.Register(api, op, func(ctx context.Context, in *pathBodyInput) (*output, error) {
				raw, err := rawBody(in.Body)
				if err != nil {
					return nil, err
				}
				return finish(ctx, in.ID, raw)
			})
		case body:
			huma.Register(api, op, func(ctx context.Context, in *bodyInput) (*output, error) {
				raw, err := rawBody(in.Body)
				if err != nil {
					return nil, err
				}
				return finish(ctx, "", raw)
			})
		case strings.Contains(path, "{id}"):
			huma.Register(api, op, func(ctx context.Context, in *pathInput) (*output, error) { return finish(ctx, in.ID, nil) })
		default:
			huma.Register(api, op, func(ctx context.Context, _ *struct{}) (*output, error) { return finish(ctx, "", nil) })
		}
	}
	register("access-workspaces", "GET", "/workspaces", false, h.workspaces)
	register("access-snapshot", "GET", "/snapshot", false, h.snapshot)
	register("access-create-book", "POST", "/books", true, h.createBook)
	register("access-update-book", "PUT", "/books/{id}", true, h.updateBook)
	register("access-delete-book", "DELETE", "/books/{id}", true, h.deleteBook)
	register("access-group-members", "PUT", "/groups/{id}/members", true, h.groupMembers)
	register("access-create-group", "POST", "/groups", true, h.createGroup)
	register("access-network", "PUT", "/network", true, h.network)
	register("access-test", "POST", "/test", true, h.connectionTest)
	register("access-invite", "POST", "/invitations", true, h.invite)
	register("access-revoke-invite", "DELETE", "/invitations/{id}", false, h.revokeInvite)
	register("access-preview-invite", "POST", "/invitations/preview", true, h.previewInvite)
	register("access-accept-invite", "POST", "/invitations/accept", true, h.acceptInvite)
	register("access-remove-member", "DELETE", "/members/{id}", false, h.removeMember)
	register("private-enroll", "POST", "/private/peers", true, h.enroll)
	register("private-rename", "PUT", "/private/peers/{id}/hostname", true, h.rename)
	register("private-bootstrap", "POST", "/private/bootstrap", true, h.bootstrap)
	register("private-change-peer", "PUT", "/private/peers/{id}", true, h.changePeer)
	register("private-revoke-peer", "DELETE", "/private/peers/{id}", false, h.revokePeer)
	register("private-sync", "POST", "/private/sync", true, h.sync)
}

func checkOrigin(r *http.Request) error {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return nil
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
			return httpapi.Fail(403, "Cross-origin workspace changes are not allowed")
		}
	}
	return nil
}
func (h *handlers) browser(ctx context.Context, manage bool) (core.Doc, bson.ObjectID, string, error) {
	if err := checkOrigin(httpapi.Request(ctx)); err != nil {
		return nil, bson.NilObjectID, "", err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, bson.NilObjectID, "", err
	}
	owner, role, err := h.app.WorkspaceAccess(ctx, user, httpapi.Request(ctx).URL.Query().Get("workspace"), manage)
	return user, owner, role, err
}
func docs(list []core.Doc) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, d := range list {
		out[i] = d
	}
	return out
}
func groupMap(list []core.Doc) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, d := range list {
		out[core.IDString(d["_id"])] = d
	}
	return out
}
func (h *handlers) members(ctx context.Context, owner bson.ObjectID) ([]bson.ObjectID, []core.Doc, error) {
	list, err := h.app.FindAll(ctx, "workspace_members", bson.M{"workspace_id": owner})
	ids := []bson.ObjectID{owner}
	for _, m := range list {
		if id, ok := core.AsOID(m["user_id"]); ok {
			ids = append(ids, id)
		}
	}
	return ids, list, err
}
func (h *handlers) preferences(ctx context.Context, owner bson.ObjectID) (policy.NetworkPreferences, error) {
	d, err := h.app.FindOne(ctx, "private_networks", bson.M{"_id": owner.Hex()})
	if err != nil {
		return policy.NetworkPreferences{}, err
	}
	if d == nil {
		d = core.Doc{}
	}
	return policy.ParseNetworkPreferences(d)
}

// Overlay helpers use typed keys to distinguish BSON ObjectIds from strings.
// Convert them once at the route boundary before looking up public peer IDs.
func privateNames(machines, peers []core.Doc) (map[string]string, map[string][]string) {
	typed := policy.AssignHostnames(docs(machines), docs(peers))
	typedAliases := policy.AliasHostnames(docs(machines), docs(peers), typed)
	labels := map[string]string{}
	aliases := map[string][]string{}
	for _, p := range peers {
		id := core.IDString(p["_id"])
		key := policy.Key(p["_id"])
		labels[id] = typed[key]
		aliases[id] = typedAliases[key]
	}
	return labels, aliases
}
