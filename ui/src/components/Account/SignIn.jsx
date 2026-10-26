import Link from "next/link";
import TextBox from "@/shared/components/TextBox";
import useAuth from "@/shared/hooks/useAuth";
import uiRoutes from "@/shared/routes/uiRoutes";
import { useState } from "react";
import { IconArrowRight, IconLoader2 } from "@tabler/icons-react";
import { MdLockOutline, MdOutlineMailOutline } from "react-icons/md";

export default function SignIn() {
  const auth = useAuth();
  const [values, setValues] = useState({ email: "", password: "" });
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const signUpDisabled = auth.authSettings?.signup_disabled === true;
  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    const next = {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email.trim())) next.email = "Enter a valid email address.";
    if (!values.password) next.password = "Enter your password.";
    setErrors(next);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      const result = await auth.signIn(values.email.trim(), values.password);
      if (result === "success") await auth.autoRoute();
      else if (result === "incorrect username") setErrors({ email: "Check your email address." });
      else if (result === "incorrect password") setErrors({ password: "That password did not match. Try again." });
      else setErrors({ form: "Could not sign in. Check your connection and try again." });
    } finally { setBusy(false); }
  }
  return <div className="w-full">
    <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Welcome back</h1>
    <p className="mb-6 mt-2 text-sm leading-6 text-muted-foreground">Sign in to continue.</p>
    <form onSubmit={submit} noValidate className="space-y-2">
      <TextBox label="Email" icon={<MdOutlineMailOutline size={19} />} placeholder="you@example.com" value={values.email} setValue={email=>setValues(v=>({...v,email}))} error={errors.email} type="email" autoComplete="username" />
      <TextBox label="Password" icon={<MdLockOutline size={19} />} placeholder="Enter your password" value={values.password} setValue={password=>setValues(v=>({...v,password}))} error={errors.password} mask autoComplete="current-password" />
      {errors.form && <p role="alert" className="pb-2 text-sm text-red-600 dark:text-red-400">{errors.form}</p>}
      <button type="submit" disabled={busy} className="!mt-6 flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-medium text-white shadow-sm transition-colors hover:bg-blue-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 disabled:cursor-wait disabled:opacity-70">{busy ? <IconLoader2 size={18} className="animate-spin" /> : null}{busy ? "Signing in…" : "Sign in"}{!busy && <IconArrowRight size={17} />}</button>
    </form>
    <div className="mt-5 text-center text-sm text-muted-foreground">{signUpDisabled ? <>Need an account? Contact your gateway administrator.</> : <>New here? <Link href={uiRoutes.signUp} className="font-medium text-primary hover:underline">Create an account</Link></>}</div>
  </div>;
}
