//! An isolated, user-owned tmux server. Dropping a handle or an attached client
//! deliberately does not stop the server or its shells.
use anyhow::{ensure, Context, Result};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[derive(Clone)]
pub struct Workspace {
    executable: PathBuf,
    terminfo: PathBuf,
    directory: PathBuf,
}

pub struct Start {
    pub cwd: PathBuf,
    pub shell: PathBuf,
    pub command: Vec<OsString>,
    pub environment: Vec<(String, String)>,
    pub history_limit: u32,
    pub mouse: bool,
    pub prefix: String,
    pub cols: u16,
    pub rows: u16,
}

impl Workspace {
    /// `directory` must already be a private directory for this workspace.
    /// The executable and terminfo come from the verified bundled runtime.
    pub fn open(executable: PathBuf, terminfo: PathBuf, directory: PathBuf) -> Result<Self> {
        let metadata = fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "invalid terminal workspace directory"
        );
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "terminal workspace directory must be private and owned by the current user"
        );
        ensure!(
            directory.is_absolute() && directory.join("tmux.sock").as_os_str().len() < 100,
            "terminal workspace socket path must be absolute and shorter than 100 bytes"
        );
        ensure!(
            executable.is_absolute() && terminfo.is_absolute(),
            "terminal runtime paths must be absolute"
        );
        Ok(Self {
            executable,
            terminfo,
            directory,
        })
    }

    pub fn socket(&self) -> PathBuf {
        self.directory.join("tmux.sock")
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .arg("-S")
            .arg(self.socket())
            .arg("-f")
            .arg(self.directory.join("tmux.conf"))
            .env_remove("TMUX")
            .env_remove("TMUX_PANE")
            .env("TERMINFO", &self.terminfo);
        command
    }

    pub fn start(&self, start: &Start) -> Result<()> {
        crate::protocol::dimensions(start.cols, start.rows)?;
        ensure!(
            (1000..=200_000).contains(&start.history_limit),
            "invalid terminal history limit"
        );
        ensure!(
            start.cwd.is_absolute() && start.cwd.is_dir(),
            "terminal working directory does not exist"
        );
        ensure!(
            start.shell.is_absolute() && start.shell.is_file(),
            "terminal shell must be an absolute executable path"
        );
        ensure!(
            valid_prefix(&start.prefix),
            "prefix must be C-a through C-z or F1 through F12"
        );
        for (key, value) in &start.environment {
            ensure!(
                !key.is_empty()
                    && !key.as_bytes()[0].is_ascii_digit()
                    && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && !value.contains('\0'),
                "invalid terminal environment variable"
            );
        }
        ensure!(!self.is_alive(), "terminal workspace already exists");
        let config = format!(
            "set -g exit-empty on\nset -g destroy-unattached off\nset -g remain-on-exit off\n\
             set -g history-limit {}\nset -g mouse {}\nset -g default-terminal tmux-256color\n\
             set -g set-clipboard on\nset -s escape-time 10\n\
             unbind C-b\nset -g prefix {}\nbind {} send-prefix\n\
             bind-key -n F7 copy-mode -u\n\
             bind-key -T copy-mode F7 send-keys -X cancel\n\
             bind-key -T copy-mode-vi F7 send-keys -X cancel\n\
             set -g status-position bottom\nset -g status-right 'PortHub | {} ? help | {} d detach'\n",
            start.history_limit, if start.mouse { "on" } else { "off" },
            start.prefix, start.prefix, start.prefix, start.prefix,
        );
        let path = self.directory.join("tmux.conf");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("create private terminal configuration")?;
        file.write_all(config.as_bytes())?;
        file.sync_all()?;
        let mut command = self.command();
        command
            .arg("new-session")
            .arg("-d")
            .arg("-s")
            .arg("workspace")
            .arg("-x")
            .arg(start.cols.to_string())
            .arg("-y")
            .arg(start.rows.to_string())
            .arg("-c")
            .arg(&start.cwd);
        for (key, value) in &start.environment {
            command.arg("-e").arg(format!("{key}={value}"));
        }
        // tmux interprets a singleton command as shell text. Use its multi-
        // argument exec form and a fixed POSIX trampoline, with user values
        // only in argv, so paths and arguments retain their literal meaning.
        command.env("SHELL", &start.shell);
        command.args(["--", "/bin/sh", "-c", "exec \"$@\"", "porthub-terminal"]);
        if start.command.is_empty() {
            command.arg(&start.shell);
        } else {
            command.args(&start.command);
        }
        let output = command
            .output()
            .context("start bundled terminal multiplexer")?;
        checked(output)?;
        // New panes/windows use the same explicitly selected shell.
        checked(
            self.command()
                .args(["set-option", "-g", "default-shell"])
                .arg(&start.shell)
                .output()?,
        )?;
        Ok(())
    }

    pub fn is_alive(&self) -> bool {
        self.command()
            .args(["has-session", "-t", "=workspace"])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    pub fn last_activity(&self) -> Result<i64> {
        let output = checked(
            self.command()
                .args([
                    "display-message",
                    "-p",
                    "-t",
                    "=workspace:",
                    "#{session_activity}",
                ])
                .output()?,
        )?;
        Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
    }

    /// Every client attaches to the same session, so window changes and panes
    /// are shared. Read-only is also enforced here, in addition to the gateway.
    pub fn attach(&self, read_only: bool) -> Command {
        let mut command = self.command();
        command.args(["attach-session", "-t", "=workspace"]);
        if read_only {
            command.arg("-r");
        }
        command
    }

    pub fn stop(&self) -> Result<()> {
        if self.is_alive() {
            checked(self.command().arg("kill-server").output()?)?;
        }
        Ok(())
    }

    pub fn capture(&self, pane: &str, history: u32) -> Result<String> {
        ensure!(
            pane.starts_with('%')
                && pane[1..].bytes().all(|b| b.is_ascii_digit())
                && pane.len() > 1,
            "invalid terminal pane identity"
        );
        ensure!(history <= 200_000, "terminal history request exceeds limit");
        let output = checked(
            self.command()
                .args(["capture-pane", "-p", "-t", pane, "-S"])
                .arg(format!("-{history}"))
                .output()?,
        )?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix
        .strip_prefix("C-")
        .is_some_and(|key| key.len() == 1 && key.as_bytes()[0].is_ascii_lowercase())
        || prefix
            .strip_prefix('F')
            .and_then(|key| key.parse::<u8>().ok())
            .is_some_and(|n| (1..=12).contains(&n))
}

fn checked(output: Output) -> Result<Output> {
    ensure!(
        output.status.success(),
        "terminal multiplexer: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

/// Create only the workspace leaf; never relax an existing directory's mode.
pub fn create_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    ensure!(
        fs::metadata(path)?.permissions().mode() & 0o077 == 0,
        "terminal directory is not private"
    );
    Ok(())
}
