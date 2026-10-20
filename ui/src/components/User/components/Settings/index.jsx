import SearchSelect from "@/components/ui/search-select";
import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useDispatch } from "react-redux";
import { AiOutlineEye, AiOutlineEyeInvisible } from "react-icons/ai";
import { FaSignOutAlt } from "react-icons/fa";
import { FiEdit3, FiPlus, FiRefreshCw, FiSend, FiTrash2, FiUpload } from "react-icons/fi";
import apiRoutes from "@/shared/routes/apiRoutes";
import uiRoutes from "@/shared/routes/uiRoutes";
import useAuth from "@/shared/hooks/useAuth";
import useToast from "@/shared/hooks/useToast";
import { authActions } from "@/redux/features/authSlice";
import Link from "next/link";
import { PageHeader } from "@/components/ui/workspace";
import { IconUser, IconShieldLock, IconBell, IconPalette, IconSun, IconMoon, IconDeviceMobile, IconCheck, IconDeviceDesktop, IconArrowUpRight } from "@tabler/icons-react";
import useTheme from "@/shared/hooks/useTheme";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog } from "@/components/ui/dialog";

const toggleTrackClass = (checked) =>
  `relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
    checked ? "bg-primary" : "bg-control"
  }`;
const toggleThumbClass = (checked) =>
  `inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
    checked ? "translate-x-4" : "translate-x-0.5"
  }`;
const DIGEST_INTERVAL_OPTIONS = [1, 3, 6, 12, 24];

const SettingsToggle = ({ checked, onChange, label, description, disabled }) => (
  <label
    className={`flex items-center justify-between gap-4 py-2 ${
      disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"
    }`}
  >
    <span>
      <span className="block text-sm font-medium">{label}</span>
      {description ? (
        <span className="block text-xs text-muted-foreground dark:text-zinc-400">{description}</span>
      ) : null}
    </span>
    <button
      type="button"
      role="switch"
      aria-label={label}
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={toggleTrackClass(checked)}
    >
      <span className={toggleThumbClass(checked)} />
    </button>
  </label>
);

const MAX_PROFILE_PICTURE_BYTES = 10 * 1024 * 1024;

function SettingsIntro({ title, description }) {
  return <div className="pb-6"><h2 className="text-xl font-semibold tracking-tight">{title}</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p></div>;
}

function SettingsRow({ title, description, children }) {
  return <div className="grid min-w-0 gap-4 border-t border-border/70 py-6 xl:grid-cols-[190px_minmax(0,1fr)] xl:gap-8"><div><h3 className="text-sm font-semibold">{title}</h3>{description && <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>}</div><div className="min-w-0">{children}</div></div>;
}

function PasswordField({ label, field, visibilityKey, passwordForm, setPasswordForm, passwordVisibility, renderPasswordToggle, autoComplete }) {
  return <label className="block text-sm font-medium">{label}<div className="relative mt-2"><Input type={passwordVisibility[visibilityKey] ? "text" : "password"} autoComplete={autoComplete} required className="pr-10" value={passwordForm[field]} onChange={event=>setPasswordForm(current=>({...current,[field]:event.target.value}))} />{renderPasswordToggle(visibilityKey,passwordVisibility[visibilityKey])}</div></label>;
}
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
  const theme = useTheme();
  const [category, setCategory] = useState("profile");
  const [savingNavigation, setSavingNavigation] = useState(false);
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
  const [passwordEditing, setPasswordEditing] = useState(false);
  const [profilePicturePayload, setProfilePicturePayload] = useState(null);
  const [profilePictureRemoved, setProfilePictureRemoved] = useState(false);
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [isSavingPassword, setIsSavingPassword] = useState(false);
  const [sessions, setSessions] = useState([]);
  const [isLoadingSessions, setIsLoadingSessions] = useState(true);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [sessionPendingSignOut, setSessionPendingSignOut] = useState(null);

  const [telegramSettings, setTelegramSettings] = useState(null);
  const [telegramEditing, setTelegramEditing] = useState(false);
  const [telegramForm, setTelegramForm] = useState({
    botToken: "",
    chatIds: [""],
    alertsEnabled: false,
    instantAlertsEnabled: true,
    digestEnabled: true,
    digestIntervalHours: 6,
  });
  const [isLoadingTelegram, setIsLoadingTelegram] = useState(true);
  const [isSavingTelegram, setIsSavingTelegram] = useState(false);
  const [isSendingTelegramTest, setIsSendingTelegramTest] = useState(false);

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

  const applyTelegramSettings = (data) => {
    setTelegramSettings(data);
    setTelegramForm({
      botToken: "",
      chatIds: data.chat_ids?.length ? data.chat_ids : [""],
      alertsEnabled: Boolean(data.alerts_enabled),
      instantAlertsEnabled: Boolean(data.instant_alerts_enabled),
      digestEnabled: Boolean(data.digest_enabled),
      digestIntervalHours: data.digest_interval_hours || 6,
    });
  };

  const loadTelegramSettings = async () => {
    setIsLoadingTelegram(true);
    try {
      const response = await axios.get(apiRoutes.telegramSettings);
      applyTelegramSettings(response.data || {});
    } catch (requestError) {
      toast.error(
        requestError?.response?.data?.detail || "Failed to load Telegram alert settings."
      );
    } finally {
      setIsLoadingTelegram(false);
    }
  };

  useEffect(() => {
    if (user?.username) {
      loadTelegramSettings();
    }
  }, [user?.username]);

  const handleTelegramChatIdChange = (index, value) => {
    setTelegramForm((current) => {
      const chatIds = [...current.chatIds];
      chatIds[index] = value;
      return { ...current, chatIds };
    });
  };

  const handleAddTelegramChatId = () => {
    setTelegramForm((current) => ({ ...current, chatIds: [...current.chatIds, ""] }));
  };

  const handleRemoveTelegramChatId = (index) => {
    setTelegramForm((current) => ({
      ...current,
      chatIds: current.chatIds.filter((_, itemIndex) => itemIndex !== index),
    }));
  };

  const handleSaveTelegramSettings = async () => {
    const chatIds = telegramForm.chatIds.map((id) => id.trim()).filter(Boolean);

    if (telegramForm.alertsEnabled && (!telegramForm.botToken.trim() && !telegramSettings?.has_bot_token)) {
      toast.error("Add a bot token before enabling Telegram alerts.");
      return;
    }
    if (telegramForm.alertsEnabled && chatIds.length === 0) {
      toast.error("Add at least one chat or channel ID before enabling Telegram alerts.");
      return;
    }

    setIsSavingTelegram(true);
    try {
      const payload = {
        chat_ids: chatIds,
        alerts_enabled: telegramForm.alertsEnabled,
        instant_alerts_enabled: telegramForm.instantAlertsEnabled,
        digest_enabled: telegramForm.digestEnabled,
        digest_interval_hours: telegramForm.digestIntervalHours,
      };
      if (telegramForm.botToken.trim()) {
        payload.bot_token = telegramForm.botToken.trim();
      }
      const response = await axios.patch(apiRoutes.telegramSettings, payload);
      applyTelegramSettings(response.data || {});
      setTelegramEditing(false);
      toast.success("Telegram alert settings updated.");
    } catch (requestError) {
      toast.error(
        requestError?.response?.data?.detail || "Failed to update Telegram alert settings."
      );
    } finally {
      setIsSavingTelegram(false);
    }
  };

  const handleSendTelegramTest = async () => {
    setIsSendingTelegramTest(true);
    try {
      await axios.post(apiRoutes.testTelegramSettings);
      toast.success("Test message sent. Check your Telegram chat.");
    } catch (requestError) {
      toast.error(
        requestError?.response?.data?.detail || "Failed to send Telegram test message."
      );
    } finally {
      setIsSendingTelegramTest(false);
    }
  };

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
      className="absolute right-2 top-1/2 inline-flex h-7 w-7 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition hover:bg-accent hover:text-foreground"
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
    <div className="flex h-full min-h-0 justify-center">
      <div className="workspace-page">
        <PageHeader eyebrow="Your workspace" title="Settings" description="Make PortHub yours. Manage your account, security, notifications, and preferences." />
        <div className="grid min-h-0 flex-1 grid-rows-[auto_minmax(0,1fr)] gap-4 lg:grid-cols-[190px_minmax(0,1fr)] lg:grid-rows-[minmax(0,1fr)] lg:gap-7">
        <nav aria-label="Settings categories" className="grid grid-cols-4 gap-1 self-start rounded-lg bg-muted/50 p-1 lg:grid-cols-1 lg:bg-transparent lg:p-0">
          {[["profile", "Profile", "Account details", IconUser], ["security", "Security", "Passwords & devices", IconShieldLock], ["notifications", "Notifications", "Machine status alerts", IconBell], ["appearance", "Appearance", "Theme & navigation", IconPalette]].map(([id, label, description, Icon]) => <button key={id} type="button" aria-label={label} aria-pressed={category === id} className={`flex min-w-0 flex-col items-center gap-2 rounded-lg px-1 py-3 text-left text-[11px] lg:flex-row lg:items-start lg:gap-3 lg:px-3 lg:text-sm ${category === id ? "bg-surface text-foreground lg:bg-muted" : "text-muted-foreground hover:bg-muted/70 hover:text-foreground"}`} onClick={() => setCategory(id)}><Icon size={18} className={`shrink-0 lg:mt-0.5 ${category === id ? "text-blue-600 dark:text-blue-400" : ""}`} /><span className="min-w-0 lg:flex-1"><span className="block font-medium">{label}</span><span className="mt-1 hidden text-xs font-normal text-muted-foreground lg:block">{description}</span></span></button>)}
        </nav>
        <div className="data-scroll min-w-0 rounded-xl bg-surface p-5 sm:p-7">

        <section hidden={category !== "profile"}>
          <SettingsIntro title="Profile" description="Manage your identity and the email you use to access PortHub." />
          <form onSubmit={event=>{event.preventDefault();handleSaveProfile();}}>
            <SettingsRow title="Profile Photo" description="Personalise your account. PNG, JPEG or WebP, up to 10 MB.">
              <div className="flex flex-wrap items-center gap-4"><div className="flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-full bg-primary text-xl font-semibold text-white">{profilePictureSource ? <img src={profilePictureSource} alt="Profile" className="h-full w-full object-cover" /> : initials}</div><input ref={profilePictureInputRef} type="file" accept="image/png,image/jpeg,image/webp" className="hidden" onChange={handleProfilePictureChange} /><Button type="button" variant="secondary" onClick={()=>profilePictureInputRef.current?.click()}><FiUpload size={15} />Upload Photo</Button>{(profilePictureSource || savedProfilePictureSource) && <Button type="button" variant="ghost" onClick={()=>{setProfilePicturePayload(null);setProfilePictureRemoved(true);}}>Remove</Button>}</div>
            </SettingsRow>
            <SettingsRow title="Account Details" description="Your display name appears in the workspace. Your email is used to sign in.">
              <div className="space-y-5"><label className="block text-sm font-medium">Display name<Input required autoComplete="name" className="mt-2" value={profileForm.name} onChange={event=>setProfileForm(current=>({...current,name:event.target.value}))} /></label><label className="block text-sm font-medium">Email address<Input required type="email" autoComplete="email" className="mt-2" value={profileForm.email} onChange={event=>setProfileForm(current=>({...current,email:event.target.value}))} /></label></div>
            </SettingsRow>
            {emailChanged && <SettingsRow title="Confirm Email Change" description="Enter your current password to update the email used to sign in."><label className="block text-sm font-medium">Current password<div className="relative mt-2"><Input required type={passwordVisibility.profileCurrent ? "text" : "password"} autoComplete="current-password" className="pr-10" value={profileForm.currentPassword} onChange={event=>setProfileForm(current=>({...current,currentPassword:event.target.value}))} />{renderPasswordToggle("profileCurrent",passwordVisibility.profileCurrent)}</div></label></SettingsRow>}
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border pt-5"><Button type="button" variant="ghost" onClick={resetProfileForm} disabled={isSavingProfile}>Discard Changes</Button><Button type="submit" disabled={isSavingProfile}>{isSavingProfile ? "Saving…" : "Save Profile"}</Button></div>
          </form>
        </section>

        <section hidden={category !== "security"}>
          <SettingsIntro title="Security" description="Keep your account secure and review the devices that can access your workspace." />
          <SettingsRow title="Change Password" description="Use a unique password that you do not use for other accounts.">
            <form className="space-y-4" onSubmit={event=>{event.preventDefault();handleSavePassword();}}>
              <PasswordField label="Current password" field="currentPassword" visibilityKey="accountCurrent" autoComplete="current-password" {...{passwordForm,setPasswordForm,passwordVisibility,renderPasswordToggle}} />
              <div className="grid gap-4 sm:grid-cols-2"><PasswordField label="New password" field="newPassword" visibilityKey="accountNew" autoComplete="new-password" {...{passwordForm,setPasswordForm,passwordVisibility,renderPasswordToggle}} /><PasswordField label="Confirm new password" field="confirmPassword" visibilityKey="accountConfirm" autoComplete="new-password" {...{passwordForm,setPasswordForm,passwordVisibility,renderPasswordToggle}} /></div>
              <div className="flex justify-end"><Button type="submit" disabled={isSavingPassword || !passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}>{isSavingPassword ? "Updating…" : "Update Password"}</Button></div>
            </form>
          </SettingsRow>
          <SettingsRow title="Signed-in Devices" description="Review active sessions. Signing out a device requires it to log in again.">
            <div className="mb-3 flex items-center justify-between"><p className="text-xs text-muted-foreground">{sessions.length} active {sessions.length === 1 ? "session" : "sessions"}</p><Button type="button" variant="ghost" size="sm" onClick={loadSessions} disabled={isLoadingSessions}><FiRefreshCw size={14} />Refresh</Button></div>
            <div className="space-y-2">{isLoadingSessions ? <p role="status" className="py-4 text-sm text-muted-foreground">Loading devices…</p> : sessions.length ? sessions.map(session=><div key={session.id} className="flex flex-wrap items-center gap-3 rounded-lg bg-muted/60 p-4"><IconDeviceDesktop size={21} className="shrink-0 text-muted-foreground" /><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-medium">{session.device_name}</p>{session.current && <span className="rounded bg-primary/10 px-2 py-0.5 text-[11px] text-blue-600 dark:text-blue-300">This device</span>}</div><p className="mt-1 text-xs leading-5 text-muted-foreground">{session.ip || "Unknown IP"} · Active {formatRelativeTime(session.last_accessed_at,Date.now())}</p></div><Button type="button" variant="ghost" size="sm" onClick={()=>setSessionPendingSignOut(session)} disabled={activeSessionId === session.id}>{activeSessionId === session.id ? "Signing out…" : "Sign Out"}</Button></div>) : <p className="text-sm text-muted-foreground">No active devices.</p>}</div>
          </SettingsRow>
        </section>

        <section hidden={category !== "notifications"}>
          <SettingsIntro title="Notifications" description="Choose how PortHub lets you know when a machine disconnects or comes back online." />
          {isLoadingTelegram ? <p role="status" className="p-4 text-sm text-muted-foreground">Loading notification settings…</p> : <form onSubmit={event=>{event.preventDefault();handleSaveTelegramSettings();}}>
            <SettingsRow title="Telegram Connection" description="Connect a bot and choose the chats or channels that receive alerts.">
              <div className="space-y-5"><label className="block text-sm font-medium">Bot token<Input aria-label="Bot token" type="password" autoComplete="new-password" className="mt-2" placeholder={telegramSettings?.has_bot_token ? telegramSettings.bot_token_masked : "Paste your Telegram bot token"} value={telegramForm.botToken} onChange={event=>setTelegramForm(current=>({...current,botToken:event.target.value}))} /><span className="mt-2 block text-xs font-normal leading-5 text-muted-foreground">{telegramSettings?.has_bot_token ? "A token is saved. Leave this empty to keep it." : "Create a bot with BotFather on Telegram, then paste its token here."}</span></label>
              <div><p className="mb-2 text-sm font-medium">Recipient IDs</p><div className="space-y-2">{telegramForm.chatIds.map((chatId,index)=><div key={index} className="flex items-center gap-2"><Input aria-label={`Telegram recipient ${index+1}`} placeholder="Chat, user or channel ID" value={chatId} onChange={event=>handleTelegramChatIdChange(index,event.target.value)} /><Button type="button" variant="ghost" size="icon" aria-label={`Remove Telegram recipient ${index+1}`} disabled={telegramForm.chatIds.length <= 1} onClick={()=>handleRemoveTelegramChatId(index)}><FiTrash2 size={15} /></Button></div>)}</div><Button type="button" className="mt-2" variant="ghost" size="sm" onClick={handleAddTelegramChatId}><FiPlus size={14} />Add Recipient</Button></div></div>
            </SettingsRow>
            <SettingsRow title="Alert Delivery" description="Changes apply after you save. Disabled machines are excluded from alerts.">
              <div className="space-y-2"><SettingsToggle checked={telegramForm.alertsEnabled} onChange={value=>setTelegramForm(current=>({...current,alertsEnabled:value}))} label="Enable Telegram alerts" description="Allow this workspace to send machine-status messages." /><SettingsToggle checked={telegramForm.instantAlertsEnabled} onChange={value=>setTelegramForm(current=>({...current,instantAlertsEnabled:value}))} label="Instant status alerts" description="Notify when a machine goes online or offline." /><SettingsToggle checked={telegramForm.digestEnabled} onChange={value=>setTelegramForm(current=>({...current,digestEnabled:value}))} label="Offline digest" description="Send a recurring summary of machines that remain offline." /><div className="flex flex-wrap items-center justify-between gap-3 pt-3"><label htmlFor="digest-interval" className="text-sm font-medium">Digest interval</label><SearchSelect id="digest-interval" className="w-40" label="Digest interval" value={telegramForm.digestIntervalHours} onChange={value=>setTelegramForm(current=>({...current,digestIntervalHours:Number(value)}))} options={DIGEST_INTERVAL_OPTIONS.map(hours=>({value:hours,label:`Every ${hours}h`}))} /></div></div>
            </SettingsRow>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5"><Button type="button" variant="secondary" onClick={handleSendTelegramTest} disabled={isSendingTelegramTest || !telegramSettings?.has_bot_token || !telegramSettings?.chat_ids?.length}><FiSend size={14} />{isSendingTelegramTest ? "Sending…" : "Send Test"}</Button><div className="flex flex-wrap gap-2"><Button type="button" variant="ghost" onClick={()=>applyTelegramSettings(telegramSettings || {})} disabled={isSavingTelegram}>Discard Changes</Button><Button type="submit" disabled={isSavingTelegram}>{isSavingTelegram ? "Saving…" : "Save Notifications"}</Button></div></div>
          </form>}
        </section>

        <section hidden={category !== "appearance"}>
          <SettingsIntro title="Appearance" description="Choose a comfortable theme and the way you move around your workspace." />
          <SettingsRow title="Color Theme" description="Switch instantly between light and dark. This preference is saved on this device.">
            <div className="grid max-w-lg grid-cols-2 gap-4">{[["light","Light",IconSun],["dark","Dark",IconMoon]].map(([value,label,Icon])=><button key={value} type="button" aria-pressed={theme.colorScheme === value} onClick={()=>theme.toggleColorScheme(value)} className={`overflow-hidden rounded-xl p-2 text-left ${theme.colorScheme === value ? "bg-primary/10" : "bg-muted/60 hover:bg-accent"}`}><div aria-hidden="true" className={`flex h-24 overflow-hidden rounded-lg ${value === "light" ? "bg-[#f4f5f7]" : "bg-[#17181c]"}`}><div className={`w-8 shrink-0 space-y-2 p-2 ${value === "light" ? "bg-[#e4e6eb]" : "bg-[#0d0e10]"}`}>{[0,1,2,3].map(item=><span key={item} className={`block h-1.5 rounded ${item===0 ? "bg-blue-600" : value === "light" ? "bg-[#bfc4cd]" : "bg-[#41434a]"}`} />)}</div><div className="flex-1 space-y-2 p-3"><div className={`h-2 w-2/3 rounded ${value === "light" ? "bg-[#c6cbd4]" : "bg-[#51535b]"}`} /><div className={`h-11 rounded ${value === "light" ? "bg-white" : "bg-[#2b2d32]"}`} /><div className="h-1.5 w-1/3 rounded bg-blue-600" /></div></div><span className="flex items-center gap-2 px-1 pb-1 pt-3 text-sm font-medium"><Icon size={16} />{label}{theme.colorScheme === value && <IconCheck size={16} className="ml-auto text-blue-600 dark:text-blue-300" />}</span></button>)}</div>
          </SettingsRow>
          <SettingsRow title="Navigation" description="Your sidebar preference follows your account across devices."><SettingsToggle label="Compact sidebar" description="Show icons to leave more room for your machines and services." checked={user?.preferences?.nav_collapsed === true} disabled={savingNavigation} onChange={async value=>{const previous=user.preferences || {};setSavingNavigation(true);dispatch(authActions.updateAccountInfo({preferences:{...previous,nav_collapsed:value}}));try{await axios.patch(apiRoutes.userPreferences,{nav_collapsed:value});}catch{dispatch(authActions.updateAccountInfo({preferences:previous}));toast.error("Could not save navigation preference.");}finally{setSavingNavigation(false);}}} /></SettingsRow>
          <SettingsRow title="Install PortHub" description="Keep your workspace close at hand."><div className="flex items-start gap-3 rounded-lg bg-muted/60 p-4"><IconDeviceMobile size={22} className="shrink-0 text-muted-foreground" /><div><p className="text-sm font-medium">Use PortHub as an App</p><p className="mt-2 text-sm leading-6 text-muted-foreground">On iPhone, use Safari’s Share menu and choose Add to Home Screen. On desktop, choose Install App in your browser when available.</p></div></div></SettingsRow>
          <SettingsRow title="Sample Workspace" description="Explore the interface with sample data."><div className="flex flex-wrap items-center justify-between gap-3"><p className="max-w-sm text-sm leading-6 text-muted-foreground">Try machines, addresses, and traffic without changing your account.</p><Button variant="secondary" asChild><Link href="/home?demo=1">Open Sample Workspace<IconArrowUpRight size={15} /></Link></Button></div></SettingsRow>
        </section>
        </div>
        </div>
      </div>

      <Dialog opened={!!sessionPendingSignOut} onClose={()=>setSessionPendingSignOut(null)} title={sessionPendingSignOut?.current ? "Sign Out This Device?" : "Sign Out Device?"} size="sm" closeOnEscape={!activeSessionId} closeOnClickOutside={!activeSessionId}>
        <p className="text-sm leading-6 text-muted-foreground">{sessionPendingSignOut?.current ? "You will be signed out of this browser." : "This device will need to sign in again."}</p>
        <div className="my-4 rounded-lg bg-control p-3"><p className="truncate text-sm font-medium">{sessionPendingSignOut?.device_name}</p><p className="mt-1 text-xs text-muted-foreground">{sessionPendingSignOut?.ip || "Unknown IP"}</p></div>
        <div className="flex justify-end gap-2"><Button type="button" variant="secondary" disabled={!!activeSessionId} onClick={()=>setSessionPendingSignOut(null)}>Cancel</Button><Button type="button" variant="destructive" disabled={!!activeSessionId} onClick={confirmSessionSignOut}>{activeSessionId ? "Signing out…" : "Sign Out"}</Button></div>
      </Dialog>
    </div>
  );
}
