function tcpPort(value) {
  if (!Number.isInteger(value) || value < 1 || value > 65535)
    throw new Error("Choose a TCP port between 1 and 65535.");
  return value;
}

export function expandPortRange(value) {
  const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(String(value).trim());
  if (!match) throw new Error("Enter a port or a range such as 8000-8003.");
  const first = tcpPort(Number(match[1]));
  const last = tcpPort(Number(match[2] ?? match[1]));
  if (last < first || last - first >= 32)
    throw new Error("Choose up to 32 consecutive ports.");
  return Array.from({ length: last - first + 1 }, (_, i) => first + i);
}

function hostname(value) {
  if (
    typeof value === "string" &&
    value.includes(":") &&
    /^[0-9a-f:.]+$/i.test(value)
  ) {
    try {
      return new URL("http://[" + value + "]/").hostname.slice(1, -1);
    } catch {}
  }
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !value
      .split(".")
      .every((part) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(part))
  )
    throw new Error("Invalid SSH gateway or destination.");
  return value;
}

export function forwardCommand(entry, client) {
  const gateway = hostname(entry.gateway);
  const port = tcpPort(entry.sshPort);
  if (!/^pf-[a-f\d]{24}$/.test(entry.username))
    throw new Error("Invalid forwarding username.");
  if (!/^ssh-ed25519 [A-Za-z\d+/]+={0,2}$/.test(entry.hostKey))
    throw new Error("Missing gateway host key.");
  const lines = entry.privateKey.trim().split(/\r?\n/);
  if (
    lines.length < 3 ||
    lines.shift() !== "-----BEGIN OPENSSH PRIVATE KEY-----" ||
    lines.pop() !== "-----END OPENSSH PRIVATE KEY-----" ||
    !lines.every((line) => /^[A-Za-z\d+/]+={0,2}$/.test(line))
  )
    throw new Error("Invalid SSH private key.");
  const pem = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    ...lines,
    "-----END OPENSSH PRIVATE KEY-----",
  ];
  if (!entry.mappings.length || entry.mappings.length > 32)
    throw new Error("Choose 1–32 port mappings.");
  const rules = entry.mappings
    .map((mapping) => {
      const local = tcpPort(mapping.clientPort);
      if (mapping.direction === "remote")
        return `-R 127.0.0.1:${tcpPort(mapping.gatewayPort)}:127.0.0.1:${local}`;
      if (mapping.direction === "local")
        return `-L 127.0.0.1:${local}:${hostname(mapping.target)}:${tcpPort(mapping.servicePort)}`;
      throw new Error("Unknown forwarding direction.");
    })
    .join(" ");
  const known = `porthub-forward-gateway ${entry.hostKey}`;
  const args = `-N -T -a -x -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o PasswordAuthentication=no -o ConnectTimeout=10 -o CheckHostIP=no -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o ExitOnForwardFailure=yes -o HostKeyAlias=porthub-forward-gateway -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -p ${port} -l ${entry.username} ${rules} ${gateway}`;
  if (client === "powershell") {
    // Windows PowerShell consumes embedded quotes in native command arguments.
    // A relative known_hosts filename also works when the TEMP path contains spaces.
    return [
      "& { $key = $null; $kh = $null; try {",
      "$key = [IO.Path]::GetTempFileName(); $kh = [IO.Path]::GetTempFileName();",
      "$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;",
      '& icacls.exe $key /inheritance:r /grant:r "${user}:(F)" | Out-Null;',
      "if ($LASTEXITCODE) { throw 'Could not protect SSH key file' };",
      `[IO.File]::WriteAllText($key, ((@(${pem.map((x) => "'" + x + "'").join(",")}) -join [char]10) + [char]10));`,
      `[IO.File]::WriteAllText($kh, ('${known}' + [char]10), [Text.Encoding]::ASCII);`,
      "$ssh = (Get-Command ssh.exe -CommandType Application -ErrorAction Stop).Source;",
      "Push-Location -LiteralPath ([IO.Path]::GetDirectoryName($kh)) -ErrorAction Stop; try {",
      `& $ssh -F NUL -i $key -o ("UserKnownHostsFile=./" + [IO.Path]::GetFileName($kh)) ${args}`,
      "} finally { Pop-Location }",
      "} finally { try { if ($null -ne $key) { [IO.File]::Delete($key) } } finally { if ($null -ne $kh) { [IO.File]::Delete($kh) } } } }",
    ].join(" ");
  }
  if (client !== "openssh") throw new Error("Choose an SSH client.");
  const script = `umask 077; d=$(mktemp -d) || exit 1; trap 'rm -f "$d/key" "$d/hosts"; rmdir "$d"' EXIT; trap 'exit 1' HUP INT TERM; printf '%s\\n' ${pem.map((x) => "'" + x + "'").join(" ")} > "$d/key" && printf '%s\\n' '${known}' > "$d/hosts" && ssh -F /dev/null -i "$d/key" -o "UserKnownHostsFile=\\"$d/hosts\\"" ${args}`;
  return "sh -c '" + script.replaceAll("'", "'\\''") + "'";
}
