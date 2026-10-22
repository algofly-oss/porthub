import { useState } from "react";
import axios from "axios";
import { IconCopy } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import { Dialog } from "@/components/ui/dialog";
import { API, errorText } from "./shared";

export default function InviteEditor({ role, params, onClose, onSaved }) {
  const [email, setEmail] = useState(""),
    [memberRole, setMemberRole] = useState("member"),
    [busy, setBusy] = useState(false),
    [link, setLink] = useState(""),
    [error, setError] = useState("");
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const response = await axios.post(
        `${API}/invitations`,
        { email, role: memberRole },
        { params },
      );
      setLink(`${location.origin}/join#${response.data.token}`);
      await onSaved();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog opened onClose={onClose} title="Invite to Workspace">
      <p className="mb-5 text-sm leading-6 text-muted-foreground">
        Invitations expire after seven days and can be used once. Membership
        alone grants no private connectivity.
      </p>
      {!link ? (
        <form onSubmit={submit} className="space-y-4">
          <label className="block text-sm font-medium">
            Email
            <Input
              className="mt-2"
              type="email"
              aria-label="Invite email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>
          <label className="block text-sm font-medium">
            Workspace role
            <SearchSelect
              className="mt-2"
              label="Invitation role"
              value={memberRole}
              onChange={setMemberRole}
              options={[
                { value: "member", label: "Member · view policies" },
                ...(role === "owner"
                  ? [
                      {
                        value: "admin",
                        label: "Administrator · manage policies",
                      },
                    ]
                  : []),
              ]}
            />
          </label>
          {error && (
            <p role="alert" className="text-sm text-red-500">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create Invitation"}
            </Button>
          </div>
        </form>
      ) : (
        <div>
          <label className="block text-sm font-medium">
            Share this invitation
            <Input
              aria-label="Invitation link"
              className="mt-2 text-xs"
              value={link}
              readOnly
              onFocus={(event) => event.target.select()}
            />
          </label>
          <p className="mt-3 text-xs leading-5 text-muted-foreground">
            Send this link to {email}. It is shown only now and is not emailed
            automatically.
          </p>
          <div className="mt-5 flex justify-end gap-2">
            <Button
              variant="secondary"
              onClick={async () => {
                try {
                  if (navigator.clipboard)
                    await navigator.clipboard.writeText(link);
                  else {
                    const input = document.querySelector(
                      'input[aria-label="Invitation link"]',
                    );
                    input.select();
                    document.execCommand("copy");
                  }
                } catch {
                  setError("Select the link above and copy it manually.");
                }
              }}
            >
              <IconCopy size={15} />
              Copy Link
            </Button>
            <Button onClick={onClose}>Done</Button>
          </div>
          {error && (
            <p role="alert" className="mt-3 text-sm text-red-500">
              {error}
            </p>
          )}
        </div>
      )}
    </Dialog>
  );
}
