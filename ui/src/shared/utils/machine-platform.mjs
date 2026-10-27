let regions;
try { regions = new Intl.DisplayNames(["en"], { type: "region", fallback: "none" }); } catch {}

export function countryDetails(code = "") {
  code = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(code) || ["XX", "ZZ"].includes(code)) return { flag: "", name: "" };
  return {
    flag: String.fromCodePoint(...[...code].map(letter => letter.codePointAt(0) + 127397)),
    name: regions?.of(code) || "Country unavailable",
  };
}

export function platformLabel(os, name = "", arch = "") {
  const base = { linux: name || "Linux · Distribution not reported", macos: "macOS", windows: "Windows" }[os] || "";
  return base ? `${base}${arch ? ` · ${arch}` : ""}` : "";
}
