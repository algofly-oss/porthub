import { IconMoon, IconSun } from "@tabler/icons-react";
import useTheme from "@/shared/hooks/useTheme";

export default function DarkThemeToggle({ collapsed = false, compact = false }) {
  const theme = useTheme();
  const label = theme.isDarkTheme ? "Switch to light theme" : "Switch to dark theme";
  return <button type="button" onClick={() => theme.toggleColorScheme()} title={label} aria-label={label}
    className={`flex shrink-0 items-center gap-3 rounded-md text-sm text-muted-foreground hover:bg-accent hover:text-foreground ${compact ? "h-8 w-8 justify-center" : collapsed ? "h-10 w-10 justify-center" : "h-10 w-full px-3"}`}>
    {theme.isDarkTheme ? <IconSun size={20} /> : <IconMoon size={20} />}
    {!collapsed && !compact && <span>{theme.isDarkTheme ? "Light appearance" : "Dark appearance"}</span>}
  </button>;
}
