import { useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import useAuth from "@/shared/hooks/useAuth";
import uiRoutes from "@/shared/routes/uiRoutes";

export default function App(props: any) {
  const router = useRouter();
  const auth = useAuth();

  useEffect(() => {
    auth.autoRoute();
  }, []);

  return null;
}
