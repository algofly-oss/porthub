import UserHome from "@/components/User";
import useAuth from "@/shared/hooks/useAuth";
import { useEffect } from "react";
import SessionStatus from "@/components/Account/SessionStatus";

export default function App(props: any) {
  const auth = useAuth();

  useEffect(() => {
    auth.autoRoute();
  }, []);

  return auth.user?.username ? <UserHome /> : <SessionStatus error={auth.connectionError} onRetry={() => auth.autoRoute()} />;
}
