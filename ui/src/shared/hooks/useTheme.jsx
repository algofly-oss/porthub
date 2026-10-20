import { useMantineColorScheme } from "@mantine/core";

export default function useTheme() {
  const { colorScheme, toggleColorScheme: changeColorScheme } = useMantineColorScheme();

  const toggleColorScheme = (value) => {
    if (typeof value !== "string") {
      value = null;
    }

    changeColorScheme(value || (colorScheme === "dark" ? "light" : "dark"));
  };

  const isDarkTheme = colorScheme === "dark";
  const setDarkTheme = (value) => {
    changeColorScheme(value ? "dark" : "light");
  };

  return { colorScheme, toggleColorScheme, isDarkTheme, setDarkTheme };
}
