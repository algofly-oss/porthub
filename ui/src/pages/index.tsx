import { useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import useAuth from "@/shared/hooks/useAuth";
import uiRoutes from "@/shared/routes/uiRoutes";
import SessionStatus from "@/components/Account/SessionStatus";

export default function App(props: any) {
  const router = useRouter();
  const auth = useAuth();

  useEffect(() => {
    auth.autoRoute();
  }, []);

  return <SessionStatus error={auth.connectionError} onRetry={() => auth.autoRoute()} />;
}
