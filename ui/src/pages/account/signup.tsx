import { useEffect } from "react";
import AuthShell from "@/components/Account/AuthShell";
import SignUp from "@/components/Account/SignUp";
import useAuth from "@/shared/hooks/useAuth";
import uiRoutes from "@/shared/routes/uiRoutes";

export default function App(props: any) {
  const auth = useAuth();

  useEffect(() => {
    auth.autoRoute(uiRoutes.signUp);
  }, []);

  return <AuthShell><SignUp /></AuthShell>;
}
