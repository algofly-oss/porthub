// Package groups ports api/router/groups (machine groups).
package groups

import (
	"context"
	"net/http"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type handlers struct{ app *core.App }

type out struct{ Body map[string]any }

func reply(msg string, data any) *out {
	return &out{Body: map[string]any{"msg": msg, "data": data}}
}

// createBody, updateBody and deleteBody document MachineGroupCreate / MachineGroupUpdate / MachineGroupDelete.
type createBody struct {
	Name         string `json:"name" minLength:"1" example:"Production"`
	pymodel.Body `json:"-"`
}

type updateBody struct {
	DataID       string `json:"data_id" minLength:"1"`
	Name         string `json:"name" minLength:"1" example:"Production"`
	pymodel.Body `json:"-"`
}

type deleteBody struct {
	DataID       string `json:"data_id" minLength:"1"`
	pymodel.Body `json:"-"`
}

type createIn struct{ Body *createBody }
type updateIn struct{ Body *updateBody }
type deleteIn struct{ Body *deleteBody }

// parseGroup validates constr(min_length=1) fields in declaration order.
func parseGroup(model *pymodel.Model, keys ...string) (map[string]string, error) {
	values := map[string]string{}
	for _, key := range keys {
		if s, ok := model.ReqStr(key); ok && model.MinLen(s, 1, key) {
			values[key] = s
		}
	}
	return values, model.Err()
}

// SerializeGroup mirrors serialize_machine_group.
func SerializeGroup(group core.Doc) map[string]any {
	return map[string]any{
		"_id":        core.IDString(group["_id"]),
		"user_id":    core.IDString(group["user_id"]),
		"name":       core.JSON(core.Get(group, "name", "")),
		"sort_order": core.JSON(core.Get(group, "sort_order", 0)),
		"created_at": core.JSON(group["created_at"]),
		"updated_at": core.JSON(group["updated_at"]),
	}
}

func Register(api huma.API, app *core.App) {
	h := &handlers{app}
	tags := []string{"Machine groups"}
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: "/api/groups" + path, Summary: summary, Tags: tags, SkipValidateBody: true}
	}
	huma.Register(api, op("add-machine-group", http.MethodPost, "/add", "Add Machine Group"), h.add)
	huma.Register(api, op("list-machine-groups", http.MethodGet, "/list", "List Machine Groups"), h.list)
	huma.Register(api, op("update-machine-group", http.MethodPut, "/update", "Update Machine Group"), h.update)
	huma.Register(api, op("delete-machine-group", http.MethodPost, "/delete", "Delete Machine Group"), h.delete)
}

func (h *handlers) add(ctx context.Context, in *createIn) (*out, error) {
	model, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseGroup(model, "name")
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	name := pymodel.Strip(data["name"])
	if name == "" {
		return nil, httpapi.Fail(400, "Group name is required")
	}
	count, err := h.app.C("machine_groups").CountDocuments(ctx, bson.M{"user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	now := core.Now()
	result, err := h.app.C("machine_groups").InsertOne(ctx, bson.D{
		{Key: "user_id", Value: user["_id"]},
		{Key: "name", Value: name},
		{Key: "sort_order", Value: int(count)},
		{Key: "created_at", Value: now},
		{Key: "updated_at", Value: now},
	})
	if err != nil {
		return nil, err
	}
	created, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": result.InsertedID})
	if err != nil {
		return nil, err
	}
	return reply("Group created successfully", SerializeGroup(created)), nil
}

func (h *handlers) list(ctx context.Context, _ *struct{}) (*out, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := h.app.FindAll(ctx, "machine_groups", bson.M{"user_id": user["_id"]},
		options.Find().SetSort(core.Sort("sort_order", 1, "created_at", 1)))
	if err != nil {
		return nil, err
	}
	data := []any{}
	for _, g := range groups {
		data = append(data, SerializeGroup(g))
	}
	return reply("Groups listed successfully", data), nil
}

func (h *handlers) userGroup(ctx context.Context, user core.Doc, dataID string) (bson.ObjectID, core.Doc, error) {
	id, err := core.ParseOID(dataID, "Invalid group id")
	if err != nil {
		return id, nil, err
	}
	group, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": id, "user_id": user["_id"]})
	if err != nil {
		return id, nil, err
	}
	if group == nil {
		return id, nil, httpapi.Fail(400, "Group not found")
	}
	return id, group, nil
}

func (h *handlers) update(ctx context.Context, in *updateIn) (*out, error) {
	model, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseGroup(model, "data_id", "name")
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	name := pymodel.Strip(data["name"])
	if name == "" {
		return nil, httpapi.Fail(400, "Group name is required")
	}
	id, _, err := h.userGroup(ctx, user, data["data_id"])
	if err != nil {
		return nil, err
	}
	if _, err := h.app.C("machine_groups").UpdateOne(ctx, bson.M{"_id": id},
		bson.M{"$set": bson.D{{Key: "name", Value: name}, {Key: "updated_at", Value: core.Now()}}}); err != nil {
		return nil, err
	}
	updated, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": id})
	if err != nil {
		return nil, err
	}
	return reply("Group updated successfully", SerializeGroup(updated)), nil
}

func (h *handlers) delete(ctx context.Context, in *deleteIn) (*out, error) {
	model, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseGroup(model, "data_id")
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, group, err := h.userGroup(ctx, user, data["data_id"])
	if err != nil {
		return nil, err
	}
	now := core.Now()
	machines := h.app.C("machines")
	if _, err := machines.UpdateMany(ctx, bson.M{"user_id": user["_id"], "group_ids": id},
		bson.M{"$pull": bson.M{"group_ids": id}, "$set": bson.M{"updated_at": now}}); err != nil {
		return nil, err
	}
	if _, err := machines.UpdateMany(ctx, bson.M{"user_id": user["_id"], "group_id": id},
		bson.M{"$unset": bson.M{"group_id": ""}, "$set": bson.M{"updated_at": now}}); err != nil {
		return nil, err
	}
	if _, err := h.app.C("machine_groups").DeleteOne(ctx, bson.M{"_id": id}); err != nil {
		return nil, err
	}
	return reply("Group deleted successfully", SerializeGroup(group)), nil
}
