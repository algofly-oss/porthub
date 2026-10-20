/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./pages/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",

    // Or if using `src` directory:
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: { colors: {
      zinc: { 950: "#09090b" }, amber: { 950: "#451a03" }, red: { 950: "#450a0a" },
      background: "hsl(var(--background) / <alpha-value>)", foreground: "hsl(var(--foreground) / <alpha-value>)",
      surface: "hsl(var(--surface) / <alpha-value>)",
      dialog: "hsl(var(--dialog) / <alpha-value>)", control: "hsl(var(--control) / <alpha-value>)",
      muted: "hsl(var(--muted) / <alpha-value>)", "muted-foreground": "hsl(var(--muted-foreground) / <alpha-value>)",
      border: "hsl(var(--border) / <alpha-value>)", input: "hsl(var(--input) / <alpha-value>)", accent: "hsl(var(--accent) / <alpha-value>)",
      primary: { DEFAULT: "#2563eb", hover: "#1d4ed8" },
    } },
  },
  plugins: [require("flowbite/plugin")],
};
