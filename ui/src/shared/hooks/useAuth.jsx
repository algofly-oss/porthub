import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { useSelector, useDispatch } from "react-redux";
import { authSelector, authActions } from "../../redux/features/authSlice";
import axios from "axios";
import apiRoutes from "../routes/apiRoutes";
import uiRoutes from "../routes/uiRoutes";

let accountRequest = null;
let accountController = null;
let accountEpoch = 0;
function invalidateAccountRequest() {
  accountEpoch += 1;
  accountController?.abort();
  accountController = null;
  accountRequest = null;
}

export default function useAuth() {
  const user = useSelector(authSelector);
  const connectionError = useSelector(state => state.auth.connectionError);
  const dispatch = useDispatch();
  const router = useRouter();
  const [authSettings, setAuthSettings] = useState(null);

  useEffect(() => {
    if (!user?.username) {
      getAccountInfo().catch(() => {});
    }
    getAuthSettings();
    const reconnect = () => {
      if (document.visibilityState !== "hidden") getAccountInfo().then(data => {
        if (data && !data.username && router.pathname === uiRoutes.home) router.replace(uiRoutes.signIn);
      }).catch(() => {});
    };
    window.addEventListener("online", reconnect);
    window.addEventListener("pageshow", reconnect);
    document.addEventListener("visibilitychange", reconnect);
    return () => {
      window.removeEventListener("online", reconnect);
      window.removeEventListener("pageshow", reconnect);
      document.removeEventListener("visibilitychange", reconnect);
    };
  }, []);

  const clearStorage = () => {
    invalidateAccountRequest();
    // remove all user data except theme preference
    const theme = localStorage.theme || "light";
    localStorage.clear();
    sessionStorage.clear();
    localStorage.theme = theme;
    dispatch(authActions.resetAccountInfo());
  };

  const getAccountInfo = async () => {
    const epoch = accountEpoch;
    if (!accountRequest) {
      accountController = new AbortController();
      accountRequest = axios.get(apiRoutes.accountInfo, {
        timeout: 20000,
        signal: accountController.signal,
        headers: { "Cache-Control": "no-store" },
      });
    }
    const request = accountRequest;
    try {
      const response = await request;
      if (epoch !== accountEpoch) return null;
      if (!response?.data?.username) throw new Error("Account response is unavailable");
      dispatch(authActions.setAccountInfo(response.data));
      return response.data;
    } catch (error) {
      if (epoch !== accountEpoch) return null;
      const status = error?.response?.status;
      const signedOut = status === 401 ||
        (status === 400 && error?.response?.data?.detail === "User not logged in");
      if (signedOut) {
        dispatch(authActions.resetAccountInfo());
        return {};
      }
      dispatch(authActions.accountUnavailable());
      throw error;
    } finally {
      if (accountRequest === request) {
        accountRequest = null;
        accountController = null;
      }
    }
  };

  const getAuthSettings = async () => {
    return await axios
      .get(apiRoutes.authSettings)
      .then((res) => {
        setAuthSettings(res.data || {});
        return res.data || {};
      })
      .catch(() => {
        const fallbackSettings = {
          signup_disabled: false,
          signup_enabled: true,
        };
        setAuthSettings(fallbackSettings);
        return fallbackSettings;
      });
  };

  const signUp = async (name, username, password) => {
    invalidateAccountRequest();
    try {
      const response = await axios.post(apiRoutes.signUp, {
        name,
        username,
        password,
      });
      if (response?.data?.msg === "success") {
        await getAccountInfo();
      }
      return response?.data?.msg;
    } catch (error) {
      return error?.response?.data?.detail;
    }
  };

  const signIn = async (username, password) => {
    invalidateAccountRequest();
    try {
      const response = await axios.post(apiRoutes.signIn, {
        username,
        password,
      });
      if (response?.data?.msg === "success") {
        await getAccountInfo();
      }
      return response?.data?.msg;
    } catch (error) {
      return error?.response?.data?.detail;
    }
  };

  const signOut = async (args) => {
    return await axios
      .post(apiRoutes.signOut, {}, { withCredentials: true })
      .then((res) => {
        clearStorage();
        if (args?.redirect) {
          router.replace(uiRoutes.signIn);
        }
      })
      .catch((err) => {
        console.log(err);
      });
  };

  const autoRoute = async (redirectUrl) => {
    await getAccountInfo().then((data) => {
      if (data === null) return;
      switch (data?.role) {
        case "admin":
          if (router.pathname !== uiRoutes.home) router.push(uiRoutes.home);
          break;
        case "user":
          if (router.pathname !== uiRoutes.home) router.push(uiRoutes.home);
          break;
        default:
          if (router.pathname !== (redirectUrl || uiRoutes.signIn)) router.replace(redirectUrl || uiRoutes.signIn);
          break;
      }
    }).catch(() => {});
  };

  return {
    user,
    authSettings,
    connectionError,
    signUp,
    signIn,
    signOut,
    getAccountInfo,
    getAuthSettings,
    autoRoute,
  };
}
