import { inventoryUrl } from "@/shared/utils/inventory-resource.mjs";
import useInventoryPage from "@/shared/hooks/useInventoryPage";
import InventorySelect from "@/components/ui/inventory-select";
import { useEffect, useState } from "react";
import axios from "axios";
import { Switch } from "@mantine/core";
import {
  IconChevronLeft,
  IconChevronRight,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { API, blankRule, errorText, DirtyGuard, MultiEntities } from "./shared";

function LoadedBookEditor({
  book,
  initialIndex,
  groups,
  options,
  manage,
  params,
  onClose,
  onSaved,
}) {
  const [form, setForm] = useState(() => structuredClone(book)),
    [index, setIndex] = useState(initialIndex),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const rule = form.rules[index],
    dirty = JSON.stringify(form) !== JSON.stringify(book);
  const update = (field, value) =>
    setForm((old) => ({ ...old, [field]: value }));
  const updateRule = (field, value) =>
    setForm((old) => ({
      ...old,
      rules: old.rules.map((r, i) =>
        i === index ? { ...r, [field]: value } : r,
      ),
    }));
  async function save(event) {
    event.preventDefault();
    if(!form.group_id){setError("Choose an organising group.");return;}
    const incomplete = form.rules.findIndex(
      (item) =>
        !item.name.trim() || !item.sources.length || !item.destinations.length,
    );
    if (incomplete !== -1) {
      setIndex(incomplete);
      setError(`Rule ${incomplete + 1} needs a name, source and destination.`);
      return;
    }
    setBusy(true);
    setError("");
    try {
      await axios({
        method: book._id ? "put" : "post",
        url: `${API}/books${book._id ? `/${book._id}` : ""}`,
        params,
        data: {
          name: form.name,
          group_id: form.group_id,
          enabled: form.enabled,
          revision: form.revision,
          rules: form.rules,
        },
      });
      await onSaved();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <DirtyGuard dirty={dirty && manage} busy={busy} onClose={onClose}>
      {(close) => (
        <WorkspaceDrawer
          opened
          onClose={close}
          title={book._id ? `${manage ? "Edit" : "View"} Policy` : "New Policy"}
          size="xl"
          fixedHeight="min(740px, 90dvh)"
          animate={false}
        >
          <form
            onSubmit={save}
            className="flex min-h-0 flex-1 flex-col overflow-hidden"
          >
            <div className="data-scroll space-y-4 pb-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-sm font-medium">
                  Policy name
                  <Input
                    className="mt-2"
                    aria-label="Policy name"
                    value={form.name}
                    maxLength={80}
                    onChange={(event) => update("name", event.target.value)}
                    disabled={!manage}
                    required
                  />
                </label>
                <label className="text-sm font-medium">
                  Organising group
                  <InventorySelect kind="access-groups" className="mt-2" label="Policy group" value={form.group_id} selected={book.group_name ? {_id:book.group_id,name:book.group_name} : undefined} filters={params} onChange={value=>update("group_id",value)} disabled={!manage} placeholder="Create a group first"/>
                </label>
              </div>
              <div className="flex items-center justify-between gap-3 rounded-lg bg-control p-3">
                <div>
                  <p className="text-sm font-medium">Policy Enabled</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    All rules below pause when disabled.
                  </p>
                </div>
                <Switch
                  aria-label="Rule book enabled"
                  checked={form.enabled}
                  disabled={!manage}
                  onChange={(event) =>
                    update("enabled", event.currentTarget.checked)
                  }
                />
              </div>
              <div className="flex items-center gap-2 border-t border-border pt-3">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label="Previous rule"
                  disabled={index === 0}
                  onClick={() => setIndex(index - 1)}
                >
                  <IconChevronLeft size={17} />
                </Button>
                <span className="text-sm font-medium">
                  {form.rules.length
                    ? `Rule ${index + 1} of ${form.rules.length}`
                    : "No rules"}
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label="Next rule"
                  disabled={index >= form.rules.length - 1}
                  onClick={() => setIndex(index + 1)}
                >
                  <IconChevronRight size={17} />
                </Button>
                {manage && (
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    className="ml-auto"
                    disabled={form.rules.length >= 100}
                    onClick={() => {
                      setIndex(form.rules.length);
                      update("rules", [...form.rules, blankRule()]);
                    }}
                  >
                    <IconPlus size={15} />
                    Rule
                  </Button>
                )}
              </div>
              {rule ? (
                <div className="space-y-4 rounded-xl bg-surface p-4">
                  <div className="flex items-end gap-2">
                    <label className="min-w-0 flex-1 text-sm font-medium">
                      Rule name
                      <Input
                        className="mt-2"
                        aria-label="Rule name"
                        required
                        disabled={!manage}
                        value={rule.name}
                        onChange={(event) =>
                          updateRule("name", event.target.value)
                        }
                        maxLength={80}
                      />
                    </label>
                    {manage && (
                      <Button
                        variant="ghost"
                        type="button"
                        size="icon"
                        aria-label="Remove this rule"
                        onClick={() => {
                          update(
                            "rules",
                            form.rules.filter((_, i) => i !== index),
                          );
                          setIndex(Math.max(0, index - 1));
                        }}
                      >
                        <IconTrash size={16} />
                      </Button>
                    )}
                  </div>
                  <MultiEntities
                    label="Source entities"
                    params={params}
                    value={rule.sources}
                    onChange={(value) => updateRule("sources", value)}
                    disabled={!manage}
                  />
                  <MultiEntities
                    label="Destination entities"
                    params={params}
                    value={rule.destinations}
                    onChange={(value) => updateRule("destinations", value)}
                    disabled={!manage}
                  />
                  <div className="grid grid-cols-2 gap-3">
                    <label className="text-sm font-medium">
                      Protocol
                      <SearchSelect
                        className="mt-2"
                        label="Rule protocol"
                        disabled={!manage}
                        value={rule.protocol}
                        onChange={(value) => {
                          updateRule("protocol", value);
                          if (["icmp", "any"].includes(value))
                            updateRule("ports", "");
                        }}
                        options={[
                          { value: "tcp", label: "TCP" },
                          { value: "udp", label: "UDP" },
                          { value: "icmp", label: "ICMP" },
                          { value: "any", label: "Any protocol" },
                        ]}
                      />
                    </label>
                    <label className="text-sm font-medium">
                      Destination ports
                      <Input
                        className="mt-2"
                        aria-label="Rule ports"
                        value={rule.ports}
                        onChange={(event) =>
                          updateRule("ports", event.target.value)
                        }
                        placeholder="All ports, or 22, 443…"
                        disabled={
                          !manage || ["icmp", "any"].includes(rule.protocol)
                        }
                        maxLength={512}
                      />
                    </label>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium">
                        Allow Both Directions
                      </p>
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">
                        Otherwise only the source initiates. Replies are
                        allowed.
                      </p>
                    </div>
                    <Switch
                      aria-label="Allow both directions"
                      checked={rule.bidirectional}
                      disabled={!manage}
                      onChange={(event) =>
                        updateRule("bidirectional", event.currentTarget.checked)
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-sm">Rule enabled</span>
                    <Switch
                      aria-label="Rule enabled"
                      checked={rule.enabled}
                      disabled={!manage}
                      onChange={(event) =>
                        updateRule("enabled", event.currentTarget.checked)
                      }
                    />
                  </div>
                </div>
              ) : (
                <p className="rounded-lg bg-surface p-4 text-sm text-muted-foreground">
                  No connections allowed. Add a rule to this policy.
                </p>
              )}
              {error && (
                <p
                  role="alert"
                  className="text-sm leading-5 text-red-600 dark:text-red-400"
                >
                  {error}
                </p>
              )}
            </div>
            <div className="flex shrink-0 items-center justify-between gap-3 border-t border-border pt-3">
              <span className="hidden text-xs text-muted-foreground sm:block">
                Saved policy only · private network not active
              </span>
              <div className="ml-auto flex gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  disabled={busy}
                  onClick={close}
                >
                  {manage ? "Cancel" : "Close"}
                </Button>
                {manage && (
                  <Button type="submit" disabled={busy || !form.group_id}>
                    {busy ? "Saving…" : "Save Policy"}
                  </Button>
                )}
              </div>
            </div>
          </form>
        </WorkspaceDrawer>
      )}
    </DirtyGuard>
  );
}

export default function BookEditor(props) {
  const [source,setSource]=useState(null),[error,setError]=useState(""),[retry,setRetry]=useState(0);
  const id=props.book._id, workspace=props.params?.workspace || "";
  useEffect(()=>{
    if(!id)return;
    const controller=new AbortController();setSource(null);setError("");
    axios.get(inventoryUrl("access-books",{workspace,ids:id,detail:true,page_size:1}),{signal:controller.signal}).then(response=>{if(!controller.signal.aborted){const row=response.data.data?.[0];if(row)setSource(row);else setError("Policy no longer exists.");}}).catch(error=>{if(!controller.signal.aborted)setError(error.response?.data?.detail || "Could not load the complete policy.");});
    return()=>controller.abort();
  },[id,workspace,retry]);
  if(!id)return <LoadedBookEditor {...props}/>;
  if(!source || source._id!==id)return <WorkspaceDrawer opened onClose={props.onClose} title="Policy" size="xl"><p role={error ? "alert" : "status"} className="p-4 text-sm text-muted-foreground">{error || "Loading complete policy…"}</p>{error && <Button type="button" variant="secondary" onClick={()=>setRetry(value=>value+1)}>Try again</Button>}</WorkspaceDrawer>;
  return <LoadedBookEditor {...props} book={source}/>;
}
