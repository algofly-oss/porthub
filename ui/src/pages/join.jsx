import { useEffect, useState } from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import axios from "axios";
import { IconShieldLock } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function JoinWorkspace() {
  const router = useRouter();
  const [token, setToken] = useState(""),
    [invite, setInvite] = useState(null),
    [user, setUser] = useState(null),
    [mode, setMode] = useState("signin"),
    [name, setName] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    const token = location.hash.slice(1);
    setToken(token);
    if (!token) {
      setError("This invitation link is incomplete.");
      return;
    }
    axios
      .post("/api/access/invitations/preview", { token })
      .then((response) => {
        if (alive) setInvite(response.data);
      })
      .catch((error) => {
        if (alive)
          setError(
            error?.response?.data?.detail ||
              "Invitation is invalid or expired.",
          );
      });
    axios
      .get("/api/auth/me")
      .then((response) => {
        if (alive) setUser(response.data);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      let workspace;
      if (user && user.username?.toLowerCase() === invite.email) {
        workspace = (
          await axios.post("/api/access/invitations/accept", { token })
        ).data.workspace_id;
      } else {
        if (user) await axios.post("/api/auth/signout");
        const response = await axios.post(
          mode === "register" ? "/api/auth/signup" : "/api/auth/signin",
          {
            username: invite.email,
            password,
            ...(mode === "register" ? { name, invitation_token: token } : {}),
          },
        );
        workspace =
          response.data.workspace_id ||
          (await axios.post("/api/access/invitations/accept", { token })).data
            .workspace_id;
      }
      await router.replace({
        pathname: "/home",
        query: { view: "access", workspace },
      });
    } catch (error) {
      const detail = error?.response?.data?.detail;
      setError(
        typeof detail === "string"
          ? detail
          : "Could not accept this invitation. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  const matching =
    user && invite && user.username?.toLowerCase() === invite.email;
  return (
    <>
      <Head>
        <title>Join Workspace · PortHub</title>
        <meta name="referrer" content="no-referrer" />
      </Head>
      <main className="flex min-h-dvh items-center justify-center bg-background p-4 text-foreground">
        <section className="w-full max-w-md rounded-2xl bg-surface p-6 sm:p-8">
          <span className="mb-5 flex h-11 w-11 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <IconShieldLock size={23} />
          </span>
          <h1 className="text-xl font-semibold">
            Join{" "}
            {invite?.workspace
              ? `${invite.workspace}'s workspace`
              : "a PortHub workspace"}
          </h1>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            An invitation grants workspace membership—not network access. An
            administrator must assign explicit connection rules.
          </p>
          {invite ? (
            <form onSubmit={submit} className="mt-6 space-y-4">
              <div className="rounded-lg bg-control p-3">
                <p className="break-all text-sm font-medium">{invite.email}</p>
                <p className="mt-1 text-xs capitalize text-muted-foreground">
                  {invite.role} · expires{" "}
                  {new Date(invite.expires_at).toLocaleDateString()}
                </p>
              </div>
              {matching ? (
                <p className="text-sm text-muted-foreground">
                  Signed in as {user.name}.
                </p>
              ) : (
                <>
                  {user && (
                    <p className="text-xs leading-5 text-amber-700 dark:text-amber-400">
                      You are signed in with a different account. Continuing
                      signs that account out.
                    </p>
                  )}
                  {mode === "register" && (
                    <label className="block text-sm font-medium">
                      Your name
                      <Input
                        className="mt-2"
                        required
                        maxLength={100}
                        autoComplete="name"
                        value={name}
                        onChange={(event) => setName(event.target.value)}
                      />
                    </label>
                  )}
                  <label className="block text-sm font-medium">
                    Password
                    <Input
                      className="mt-2"
                      type="password"
                      required
                      minLength={mode === "register" ? 12 : undefined}
                      maxLength={72}
                      autoComplete={
                        mode === "register"
                          ? "new-password"
                          : "current-password"
                      }
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                    />
                  </label>
                </>
              )}
              {error && (
                <p
                  role="alert"
                  className="text-sm leading-6 text-red-600 dark:text-red-400"
                >
                  {error}
                </p>
              )}
              <Button type="submit" className="w-full" disabled={busy}>
                {busy
                  ? "Joining…"
                  : matching
                    ? "Accept Invitation"
                    : mode === "register"
                      ? "Create Account & Join"
                      : "Sign In & Join"}
              </Button>
              {!matching && (
                <Button
                  type="button"
                  className="w-full"
                  variant="ghost"
                  disabled={busy}
                  onClick={() => {
                    setMode(mode === "register" ? "signin" : "register");
                    setError("");
                  }}
                >
                  {mode === "register"
                    ? "Already have an account? Sign in"
                    : "New to PortHub? Create an account"}
                </Button>
              )}
            </form>
          ) : (
            <p
              role={error ? "alert" : "status"}
              className={`mt-6 text-sm leading-6 ${error ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}`}
            >
              {error || "Checking invitation…"}
            </p>
          )}
        </section>
      </main>
    </>
  );
}
