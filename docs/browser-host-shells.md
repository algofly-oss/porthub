# Browser shells on an enrolled machine

On the dashboard, open the machine and choose **Shells**. When you run the dashboard installer as your Linux or macOS login user, enrollment sets up browser shells for the machine owner. The installer can elevate to install the agent while the shells run as your login user. To skip shell setup for an installation, set `PORTHUB_BROWSER_SHELLS=off` on the shell that executes the installer. Running the installer directly as root or enrolling a private-only peer skips automatic shell hosting. For an existing registration, the Shells tab shows the following manual setup command.

```sh
porthub terminal dashboard enable --owner ACCOUNT_ID --registration MACHINE_ID
```

Add `--user` if the registration is a per-user installation. The command installs an owned systemd user service on Linux or a LaunchAgent on macOS. It starts immediately and at that OS user's login. A machine that boots without a user login needs a running user service manager for hosting. Windows users can enroll a Linux distribution inside WSL and run the command there.

The local service maintains three fresh or claimed workspaces by default. Set `--slots` at enrollment to choose a capacity from one through eight. Closing a browser tab leaves its workspace alive. Exiting a shell frees a slot. The host replenishes it while the service runs. Traffic travels through the existing outbound PortHub broker connection. The system SSH daemon and host firewall keep their current configuration.

**New shell** claims one workspace for the signed-in machine owner. Select another shell to switch, or use **Open in new tab** to attach another viewer. Tabs attached to the same workspace see live input and output. Each terminal runs under the locally enrolled OS user, including that user's normal file and application access.

Under **Invite guests**, the owner can generate a read-only link and an interactive link. Anyone holding an interactive link can type as the shell user. The links permit new joins for 15 minutes. Creating a new pair replaces the previous links. Blocking invitation URLs stops new joins. Use **Remove guest** to disconnect an attached guest and revoke their recovery access.

```sh
porthub terminal dashboard status --owner ACCOUNT_ID --registration MACHINE_ID
porthub terminal dashboard disable --owner ACCOUNT_ID --registration MACHINE_ID
```

Use the same registration mode as at enrollment. Disable closes the service's workspaces and removes its startup entry. If the registration has already been removed, use the full registration identifier printed at enable time. For a temporary foreground service, use `run` in place of `enable` and terminate it to withdraw its workspaces.
