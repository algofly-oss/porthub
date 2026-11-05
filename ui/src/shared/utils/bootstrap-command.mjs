// Explicitly launch Windows PowerShell so the same copied line also works in cmd.exe.
// Unsafe URL characters become PowerShell char literals: neither parent shell can
// expand variables, percent references, backticks, or command separators from them.
function windowsUri(value) {
  const parts = [];
  let text = "";
  const flush = () => { if (text) { parts.push(`'${text}'`); text = ""; } };
  for (let index = 0; index < value.length; index++) {
    const char = value[index];
    if (/[a-zA-Z0-9:/?&=._~#,@+\-\[\]()]/.test(char)) text += char;
    else { flush(); parts.push(`[char]${value.charCodeAt(index)}`); }
  }
  flush();
  return parts.length === 1 && parts[0].startsWith("'") ? parts[0] : `('' + ${parts.join(" + ")})`;
}
export function bootstrapCommand(value, os, shell = "cmd") {
  if (!value) return "";
  const url = String(value).replace(/\/$/, "");
  try {
    const parsed = new URL(url);
    if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) return "";
  } catch { return ""; }
  if (os !== "windows") return `curl -fsSL '${url.replaceAll("'", "'\\''")}' | bash`;
  const script = `[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri ${windowsUri(`${url}/windows.ps1`)} -ErrorAction Stop | Invoke-Expression`;
  return shell === "cmd" ? `powershell.exe -NoProfile -Command "${script}"` : script;
}

export const windowsShells = [
  { id: "cmd", label: "Command Prompt" },
  { id: "powershell", label: "PowerShell 5.1" },
  { id: "pwsh", label: "PowerShell 7" },
];
export function windowsInstallerDownloads(value) {
  if (!bootstrapCommand(value, "windows")) return [];
  const base = String(value).replace(/\/$/, "");
  return [
    { label: "Download .bat", url: `${base}/windows.bat` },
    { label: "Download .ps1", url: `${base}/windows.ps1` },
  ];
}
