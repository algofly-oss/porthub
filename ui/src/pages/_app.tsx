import "@/styles/globals.css";
import Head from "next/head";
import { AppProps } from "next/app";
import { useEffect, useLayoutEffect } from "react";
import { Provider } from "react-redux";
import {
  MantineProvider,
  ColorSchemeProvider,
  ColorScheme,
} from "@mantine/core";
import { useHotkeys, useLocalStorage } from "@mantine/hooks";
import store from "../redux/store";
import { socket, SocketContext } from "../shared/contexts/socket";
import toast, { Toaster } from "react-hot-toast";
import DemoProvider from "@/shared/demo/DemoProvider";
const useBrowserLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

export default function App({ Component, pageProps }: AppProps) {
  const [colorScheme, setColorScheme] = useLocalStorage<ColorScheme>({
    key: "mantine-color-scheme",
    defaultValue: "dark",
    getInitialValueInEffect: true,
  });

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Tab") document.documentElement.setAttribute("data-keyboard-navigation", "");
    };
    const onPointerDown = () => document.documentElement.removeAttribute("data-keyboard-navigation");
    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("pointerdown", onPointerDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.documentElement.removeAttribute("data-keyboard-navigation");
    };
  }, []);

  useBrowserLayoutEffect(() => {
    document.documentElement.classList.add("theme-changing");
    document.documentElement.classList.remove("light", "dark");
    document.body.classList.remove("light", "dark");
    document.documentElement.classList.add(colorScheme);
    document.body.classList.add(colorScheme);
    // Commit the new palette before restoring interaction transitions.
    void document.documentElement.offsetHeight;
    const frame = requestAnimationFrame(() => document.documentElement.classList.remove("theme-changing"));
    return () => cancelAnimationFrame(frame);
  }, [colorScheme]);

  const toggleColorScheme = (value?: ColorScheme) => {
    if (value === colorScheme) return;
    document.documentElement.classList.add("theme-changing");
    setColorScheme(value || (colorScheme === "dark" ? "light" : "dark"));
  };
  useHotkeys([["mod+J", () => toggleColorScheme()]]);

  return (
    <div className={colorScheme}>
      <Toaster toastOptions={{ className: "!bg-dialog !text-foreground !shadow-lg" }} />
      <Head>
        <title>PortHub</title>
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="shortcut icon" href="/favicon.svg" />
        <link rel="manifest" href="/manifest.json" />
        <meta
          name="description"
          content="PortHub is a web-based port manager for your servers."
        />
        <meta name="theme-color" content={colorScheme === "dark" ? "#1f2023" : "#f4f5f7"} />
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png" />
      </Head>
      <Provider store={store}>
        <ColorSchemeProvider
          colorScheme={colorScheme}
          toggleColorScheme={toggleColorScheme}
        >
          <MantineProvider
            withNormalizeCSS
            withGlobalStyles
            theme={{ colorScheme, primaryColor: "blue", primaryShade: { light: 6, dark: 6 }, colors: { blue: ["#eff6ff", "#dbeafe", "#bfdbfe", "#93c5fd", "#60a5fa", "#3b82f6", "#2563eb", "#1d4ed8", "#1e40af", "#1e3a8a"] }, defaultRadius: "md", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', components: { Button: { defaultProps: { radius: "md" } }, Modal: { defaultProps: { radius: "lg" } } } }}
          >
            <SocketContext.Provider value={socket}>
              <DemoProvider><Component {...pageProps} /></DemoProvider>
            </SocketContext.Provider>
          </MantineProvider>
        </ColorSchemeProvider>
      </Provider>
    </div>
  );
}
