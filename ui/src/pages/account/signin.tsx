import { useEffect } from "react";
import AuthShell from "@/components/Account/AuthShell";
import SignIn from "@/components/Account/SignIn";
import useAuth from "@/shared/hooks/useAuth";

export default function App(props: any) {
  const auth = useAuth();

  useEffect(() => {
    auth.autoRoute();
  }, []);

  return <AuthShell><SignIn /></AuthShell>;
}
