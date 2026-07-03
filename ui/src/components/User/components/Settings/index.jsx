import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useDispatch } from "react-redux";
import { AiOutlineEye, AiOutlineEyeInvisible } from "react-icons/ai";
import { FaSignOutAlt } from "react-icons/fa";
import { FiEdit3, FiRefreshCw, FiTrash2, FiUpload } from "react-icons/fi";
import apiRoutes from "@/shared/routes/apiRoutes";
import uiRoutes from "@/shared/routes/uiRoutes";
import useAuth from "@/shared/hooks/useAuth";
import useToast from "@/shared/hooks/useToast";
import { authActions } from "@/redux/features/authSlice";

const panelClass =
  "overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-700 dark:bg-zinc-900";
const dividerClass = "border-zinc-200 dark:border-zinc-700";
const inputClass =
  "mt-1 w-full rounded-md border border-zinc-300 bg-zinc-50 px-3 py-2 text-sm text-zinc-900 outline-none ring-0 transition-colors focus:border-blue-500 focus:ring-0 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100";
const passwordInputClass = `${inputClass} pr-10`;
const secondaryButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800";
const primaryButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-md bg-blue-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60";
const dangerButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-md border border-red-300 bg-white px-3 py-2 text-sm font-medium text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-red-900/70 dark:bg-zinc-900 dark:text-red-300 dark:hover:bg-red-950/30";

const MAX_PROFILE_PICTURE_BYTES = 10 * 1024 * 1024;
const ALLOWED_PROFILE_PICTURE_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
]);
const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, {
  numeric: "auto",
});

function parseDate(value) {
  if (!value) return null;
  const normalized =
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T/.test(value) &&
    !/(?:z|[+-]\d{2}:?\d{2})$/i.test(value)
      ? `${value}Z`
      : value;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatCreatedAt(value) {
  const date = parseDate(value);
  if (!date) return "Never";
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}

function formatRelativeTime(value, now) {
  const date = parseDate(value);
  if (!date) return "Never";
  const diffSeconds = Math.round((date.getTime() - now) / 1000);
  const absoluteSeconds = Math.abs(diffSeconds);
  if (absoluteSeconds < 60) return relativeTimeFormatter.format(diffSeconds, "second");
  const diffMinutes = Math.round(diffSeconds / 60);
  if (Math.abs(diffMinutes) < 60) return relativeTimeFormatter.format(diffMinutes, "minute");
  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) return relativeTimeFormatter.format(diffHours, "hour");
  return relativeTimeFormatter.format(Math.round(diffHours / 24), "day");
}

const fileToImage = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const image = new Image();
      image.onload = () => resolve({ image, dataUrl: reader.result });
      image.onerror = () => reject(new Error("Failed to read profile picture"));
      image.src = reader.result;
    };
    reader.onerror = () => reject(new Error("Failed to read profile picture"));
    reader.readAsDataURL(file);
  });

const readProfilePictureFile = async (file) => {
  if (!file) return null;
  if (!ALLOWED_PROFILE_PICTURE_TYPES.has(file.type)) {
    throw new Error("Choose a PNG, JPG, or WebP image");
  }
  if (file.size > MAX_PROFILE_PICTURE_BYTES) {
    throw new Error("Profile picture must be 10 MB or smaller");
  }

  const { image, dataUrl } = await fileToImage(file);
  const maxSize = 512;
  const scale = Math.min(1, maxSize / Math.max(image.width, image.height));
  const width = Math.max(1, Math.round(image.width * scale));
  const height = Math.max(1, Math.round(image.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;

  const context = canvas.getContext("2d");
  if (!context) {
    return { data_url: dataUrl, filename: file.name, content_type: file.type };
  }

  context.drawImage(image, 0, 0, width, height);
  const outputType = file.type === "image/png" ? "image/png" : "image/jpeg";
  return {
    data_url: canvas.toDataURL(outputType, 0.86),
    filename: file.name,
    content_type: outputType,
  };
};

export default function Settings() {
  const auth = useAuth();
  const toast = useToast();
  const dispatch = useDispatch();
  const user = auth.user;
  const profilePictureInputRef = useRef(null);

  const [profileForm, setProfileForm] = useState({
    name: "",
    email: "",
    currentPassword: "",
  });
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [passwordVisibility, setPasswordVisibility] = useState({
    profileCurrent: false,
    accountCurrent: false,
    accountNew: false,
    accountConfirm: false,
  });
  const [profileEditing, setProfileEditing] = useState(false);
  const [passwordEditing, setPasswordEditing] = useState(false);
  const [profilePicturePayload, setProfilePicturePayload] = useState(null);
  const [profilePictureRemoved, setProfilePictureRemoved] = useState(false);
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [isSavingPassword, setIsSavingPassword] = useState(false);
  const [sessions, setSessions] = useState([]);
  const [isLoadingSessions, setIsLoadingSessions] = useState(true);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [sessionPendingSignOut, setSessionPendingSignOut] = useState(null);

  useEffect(() => {
    setProfileForm({
      name: user?.name || "",
      email: user?.email || user?.username || "",
      currentPassword: "",
    });
    setProfilePicturePayload(null);
    setProfilePictureRemoved(false);
  }, [user?.email, user?.name, user?.profile_picture?.data_url, user?.username]);

  const loadSessions = async () => {
    setIsLoadingSessions(true);
    try {
      const response = await axios.get(apiRoutes.listSessions);
      setSessions(response?.data?.data || []);
    } catch (requestError) {
      toast.error(requestError?.response?.data?.detail || "Failed to load active sessions.");
    } finally {
      setIsLoadingSessions(false);
    }
  };

  useEffect(() => {
    if (user?.username) {
      loadSessions();
    }
  }, [user?.username]);

  const savedProfilePictureSource = user?.profile_picture?.data_url || "";
  const profilePictureSource =
    profilePicturePayload?.data_url ||
    (!profilePictureRemoved ? savedProfilePictureSource : "");
  const initials = String(user?.name || user?.username || "P")
    .trim()
    .slice(0, 1)
    .toUpperCase();
  const emailChanged =
    profileForm.email.trim().toLowerCase() !==
    String(user?.email || user?.username || "").trim().toLowerCase();

  const togglePasswordVisibility = (key) => {
    setPasswordVisibility((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };

  const renderPasswordToggle = (key, isVisible) => (
    <button
      type="button"
      className="absolute right-2 top-1/2 inline-flex h-7 w-7 -translate-y-1/2 items-center justify-center rounded-md text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
      onClick={() => togglePasswordVisibility(key)}
      aria-label={isVisible ? "Hide password" : "Show password"}
      title={isVisible ? "Hide password" : "Show password"}
    >
      {isVisible ? <AiOutlineEyeInvisible size={18} /> : <AiOutlineEye size={18} />}
    </button>
  );

  const handleProfilePictureChange = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    try {
      const nextPayload = await readProfilePictureFile(file);
      setProfilePicturePayload(nextPayload);
      setProfilePictureRemoved(false);
    } catch (requestError) {
      toast.error(requestError?.message || "Failed to read profile picture");
    }
  };

  const resetProfileForm = () => {
    setProfilePicturePayload(null);
    setProfilePictureRemoved(false);
    setProfileForm({
      name: user?.name || "",
      email: user?.email || user?.username || "",
      currentPassword: "",
    });
  };

  const handleToggleProfileEditing = () => {
    if (profileEditing) {
      resetProfileForm();
    }
    setProfileEditing((editing) => !editing);
  };

  const handleSaveProfile = async () => {
    const name = profileForm.name.trim();
    const email = profileForm.email.trim().toLowerCase();

    if (!name || !email) {
      toast.error("Name and email are required.");
      return;
    }
    if (emailChanged && !profileForm.currentPassword) {
      toast.error("Current password is required to update email.");
      return;
    }

    setIsSavingProfile(true);
    try {
      const response = await axios.patch(apiRoutes.updateAccount, {
        name,
        email,
        current_password: emailChanged ? profileForm.currentPassword : null,
        profile_picture: profilePicturePayload,
        remove_profile_picture: profilePictureRemoved,
      });
      dispatch(authActions.setAccountInfo(response.data));
      setProfileForm((current) => ({ ...current, currentPassword: "" }));
      setProfilePicturePayload(null);
      setProfilePictureRemoved(false);
      setProfileEditing(false);
      toast.success("Account updated.");
    } catch (requestError) {
      toast.error(requestError?.response?.data?.detail || "Failed to update account.");
    } finally {
      setIsSavingProfile(false);
    }
  };

  const handleSavePassword = async () => {
    if (!passwordForm.currentPassword) {
      toast.error("Current password is required.");
      return;
    }
    if (passwordForm.newPassword.length < 8) {
      toast.error("Password must be at least 8 characters.");
      return;
    }
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast.error("New passwords do not match.");
      return;
    }

    setIsSavingPassword(true);
    try {
      const response = await axios.patch(apiRoutes.updatePassword, {
        current_password: passwordForm.currentPassword,
        new_password: passwordForm.newPassword,
      });
      dispatch(
        authActions.updateAccountInfo({
          has_password: response?.data?.has_password ?? true,
        })
      );
      setPasswordForm({
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      });
      setPasswordEditing(false);
      toast.success("Password updated.");
    } catch (requestError) {
      toast.error(requestError?.response?.data?.detail || "Failed to update password.");
    } finally {
      setIsSavingPassword(false);
    }
  };

  const confirmSessionSignOut = async () => {
    const session = sessionPendingSignOut;
    if (!session) return;

    setActiveSessionId(session.id);
    try {
      await axios.delete(`${apiRoutes.listSessions}/${session.id}`);
      setSessionPendingSignOut(null);
      if (session.current) {
        window.location.href = uiRoutes.signIn;
        return;
      }
      setSessions((current) => current.filter((item) => item.id !== session.id));
      toast.success("Session signed out.");
    } catch (requestError) {
      toast.error(requestError?.response?.data?.detail || "Failed to sign out session.");
    } finally {
      setActiveSessionId(null);
    }
  };

  return (
    <div className="flex justify-center">
      <div className="m-4 flex w-full flex-col gap-5 pb-16 md:pb-6 xl:m-8 2xl:w-[80rem]">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500">
            Settings
          </p>
          <h1 className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
            Account settings
          </h1>
          <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
            Manage your profile, password, and active sessions.
          </p>
        </div>

        <section className={panelClass}>
          <div className={`flex items-center justify-between gap-4 border-b px-5 py-4 ${dividerClass}`}>
            <div>
              <p className="text-sm font-semibold">Profile</p>
              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Update your photo, display name, and email address.
              </p>
            </div>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={handleToggleProfileEditing}
              disabled={isSavingProfile}
            >
              {!profileEditing ? <FiEdit3 size={14} /> : null}
              {profileEditing ? "Cancel" : "Edit"}
            </button>
          </div>

          <div className="space-y-5 p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
              <div className="flex h-20 w-20 shrink-0 items-center justify-center overflow-hidden rounded-full bg-blue-600 text-2xl font-semibold text-white">
                {profilePictureSource ? (
                  <img
                    src={profilePictureSource}
                    alt="Profile"
                    className="h-full w-full object-cover"
                  />
                ) : (
                  initials
                )}
              </div>

              {profileEditing ? (
                <div className="min-w-0 flex-1 space-y-3">
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="block">
                      <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                        Name
                      </span>
                      <input
                        className={inputClass}
                        value={profileForm.name}
                        onChange={(event) =>
                          setProfileForm((current) => ({
                            ...current,
                            name: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label className="block">
                      <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                        Email
                      </span>
                      <input
                        className={inputClass}
                        value={profileForm.email}
                        onChange={(event) =>
                          setProfileForm((current) => ({
                            ...current,
                            email: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <input
                      ref={profilePictureInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp"
                      className="hidden"
                      onChange={handleProfilePictureChange}
                    />
                    <button
                      type="button"
                      className={secondaryButtonClass}
                      onClick={() => profilePictureInputRef.current?.click()}
                    >
                      <FiUpload size={14} />
                      Upload
                    </button>
                    {(profilePictureSource || savedProfilePictureSource) ? (
                      <button
                        type="button"
                        className={dangerButtonClass}
                        onClick={() => {
                          setProfilePicturePayload(null);
                          setProfilePictureRemoved(true);
                        }}
                      >
                        <FiTrash2 size={14} />
                        Remove
                      </button>
                    ) : null}
                  </div>
                </div>
              ) : (
                <div>
                  <p className="text-sm font-medium">{user?.name || "Account"}</p>
                  <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                    {user?.email || user?.username}
                  </p>
                </div>
              )}
            </div>

            {profileEditing ? (
              <>
                {emailChanged ? (
                  <label className="block">
                    <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                      Current password
                    </span>
                    <div className="relative">
                      <input
                        type={passwordVisibility.profileCurrent ? "text" : "password"}
                        className={passwordInputClass}
                        value={profileForm.currentPassword}
                        onChange={(event) =>
                          setProfileForm((current) => ({
                            ...current,
                            currentPassword: event.target.value,
                          }))
                        }
                      />
                      {renderPasswordToggle(
                        "profileCurrent",
                        passwordVisibility.profileCurrent
                      )}
                    </div>
                  </label>
                ) : null}

                <div className="flex justify-end gap-2 border-t border-zinc-100 pt-4 dark:border-zinc-800">
                  <button
                    type="button"
                    className={secondaryButtonClass}
                    onClick={resetProfileForm}
                    disabled={isSavingProfile}
                  >
                    Reset
                  </button>
                  <button
                    type="button"
                    className={primaryButtonClass}
                    onClick={handleSaveProfile}
                    disabled={isSavingProfile}
                  >
                    {isSavingProfile ? "Saving..." : "Save profile"}
                  </button>
                </div>
              </>
            ) : null}
          </div>
        </section>

        <section className={panelClass}>
          <div className={`flex items-center justify-between gap-4 border-b px-5 py-4 ${dividerClass}`}>
            <div>
              <p className="text-sm font-semibold">Password</p>
              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Change the password used to sign in.
              </p>
            </div>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => setPasswordEditing((editing) => !editing)}
              disabled={isSavingPassword}
            >
              {!passwordEditing ? <FiEdit3 size={14} /> : null}
              {passwordEditing ? "Cancel" : "Update"}
            </button>
          </div>

          {passwordEditing ? (
            <div className="grid gap-3 p-5 md:grid-cols-[1fr_1fr_1fr_auto] md:items-end">
              <div className="relative">
                <input
                  type={passwordVisibility.accountCurrent ? "text" : "password"}
                  placeholder="Current password"
                  className={passwordInputClass}
                  value={passwordForm.currentPassword}
                  onChange={(event) =>
                    setPasswordForm((current) => ({
                      ...current,
                      currentPassword: event.target.value,
                    }))
                  }
                />
                {renderPasswordToggle("accountCurrent", passwordVisibility.accountCurrent)}
              </div>
              <div className="relative">
                <input
                  type={passwordVisibility.accountNew ? "text" : "password"}
                  placeholder="New password"
                  className={passwordInputClass}
                  value={passwordForm.newPassword}
                  onChange={(event) =>
                    setPasswordForm((current) => ({
                      ...current,
                      newPassword: event.target.value,
                    }))
                  }
                />
                {renderPasswordToggle("accountNew", passwordVisibility.accountNew)}
              </div>
              <div className="relative">
                <input
                  type={passwordVisibility.accountConfirm ? "text" : "password"}
                  placeholder="Confirm new password"
                  className={passwordInputClass}
                  value={passwordForm.confirmPassword}
                  onChange={(event) =>
                    setPasswordForm((current) => ({
                      ...current,
                      confirmPassword: event.target.value,
                    }))
                  }
                />
                {renderPasswordToggle("accountConfirm", passwordVisibility.accountConfirm)}
              </div>
              <button
                type="button"
                className={primaryButtonClass}
                onClick={handleSavePassword}
                disabled={isSavingPassword}
              >
                {isSavingPassword ? "Updating..." : "Update"}
              </button>
            </div>
          ) : (
            <div className="px-5 py-4 text-sm text-zinc-500 dark:text-zinc-400">
              Password fields are hidden until you choose to update them.
            </div>
          )}
        </section>

        <section className={panelClass}>
          <div className={`flex items-center justify-between gap-4 border-b px-5 py-4 ${dividerClass}`}>
            <div>
              <p className="text-sm font-semibold">Active sessions</p>
              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Review signed-in devices and revoke access when needed.
              </p>
            </div>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={loadSessions}
              disabled={isLoadingSessions}
            >
              <FiRefreshCw size={14} />
              Refresh
            </button>
          </div>

          <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {isLoadingSessions ? (
              <div className="px-5 py-6 text-sm text-zinc-500 dark:text-zinc-400">
                Loading sessions...
              </div>
            ) : sessions.length ? (
              sessions.map((session) => (
                <div
                  key={session.id}
                  className="flex items-center justify-between gap-4 px-5 py-4"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate text-sm font-medium">
                        {session.device_name}
                      </p>
                      {session.current ? (
                        <span className="rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700 dark:border-blue-500/20 dark:bg-blue-500/10 dark:text-blue-300">
                          Current
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                      {session.ip || "Unknown IP"} · Last active{" "}
                      {formatRelativeTime(session.last_accessed_at, Date.now())}
                    </p>
                    <p className="mt-1 text-xs text-zinc-500">
                      Created {formatCreatedAt(session.created_at)}
                    </p>
                  </div>
                  <button
                    type="button"
                    className={secondaryButtonClass}
                    onClick={() => setSessionPendingSignOut(session)}
                    disabled={activeSessionId === session.id}
                  >
                    <FaSignOutAlt size={14} />
                    {activeSessionId === session.id ? "Signing out..." : "Sign out"}
                  </button>
                </div>
              ))
            ) : (
              <div className="px-5 py-6 text-sm text-zinc-500 dark:text-zinc-400">
                No active sessions found.
              </div>
            )}
          </div>
        </section>
      </div>

      {sessionPendingSignOut ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 px-4 backdrop-blur-[1px]">
          <div className="w-full max-w-sm rounded-lg border border-zinc-200 bg-white p-4 shadow-lg dark:border-zinc-700 dark:bg-zinc-900">
            <p className="text-sm font-semibold">
              {sessionPendingSignOut.current
                ? "Sign out current session?"
                : "Sign out this session?"}
            </p>
            <p className="mt-2 text-sm leading-6 text-zinc-500 dark:text-zinc-400">
              {sessionPendingSignOut.current
                ? "You will be signed out of this browser."
                : "That device will need to sign in again."}
            </p>
            <div className="mt-4 rounded-md bg-zinc-50 px-3 py-2 dark:bg-zinc-900">
              <p className="truncate text-sm font-medium">
                {sessionPendingSignOut.device_name}
              </p>
              <p className="mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400">
                {sessionPendingSignOut.ip || "Unknown IP"}
              </p>
            </div>
            <div className="mt-4 flex items-center justify-end gap-2">
              <button
                type="button"
                className={secondaryButtonClass}
                onClick={() => setSessionPendingSignOut(null)}
                disabled={activeSessionId === sessionPendingSignOut.id}
              >
                Cancel
              </button>
              <button
                type="button"
                className="rounded-md bg-red-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-60"
                onClick={confirmSessionSignOut}
                disabled={activeSessionId === sessionPendingSignOut.id}
              >
                {activeSessionId === sessionPendingSignOut.id
                  ? "Signing out..."
                  : "Sign out"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
