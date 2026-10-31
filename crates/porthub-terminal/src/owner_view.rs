//! Private per-attachment presentation. Neither its panel nor its controls are
//! panes in the shared workspace. Only the inner attachment speaks to guests.
use crate::multiplexer::Workspace;
use anyhow::{ensure, Context, Result};
use std::{ffi::OsStr, fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, process::Command};

fn quote(value: &OsStr) -> Result<String> {
    let value = value.to_str().context("owner view command must be UTF-8")?;
    ensure!(!value.contains('\0'), "invalid owner view command");
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

pub struct OwnerView {
    local: Workspace,
}
impl OwnerView {
    pub fn new(shared: &Workspace, directory: std::path::PathBuf) -> Result<Self> {
        let local = shared.local_view(directory)?;
        ensure!(
            local.socket() != shared.socket(),
            "owner view must use a separate socket"
        );
        ensure!(!local.is_alive(), "owner view directory is already active");
        Ok(Self { local })
    }

    /// Run this command on the owner's terminal. The caller retains this guard
    /// until it exits; dropping it destroys only this private presentation.
    pub fn command(
        &self,
        shared: &Workspace,
        panel: &Command,
        cols: u16,
        rows: u16,
    ) -> Result<Command> {
        crate::protocol::dimensions(cols, rows)?;
        ensure!(cols >= 80, "participant sidebar needs at least 80 columns");
        let mut config = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.local.socket().with_file_name("tmux.conf"))?;
        config.write_all(b"set -s exit-unattached on\nset -g exit-empty on\nset -g status off\nset -g prefix None\nunbind -a\nunbind -a -T root\nset -g mouse on\nset -g default-terminal tmux-256color\nset -s set-clipboard on\nset -g allow-passthrough on\nset -s escape-time 10\nbind -n F8 if-shell -F '#{==:#{pane_id},%0}' 'select-pane -t %1' 'select-pane -t %0'\nbind -n MouseDown1Pane select-pane -t = \\; send-keys -M\nbind -n MouseDrag1Pane send-keys -M\nbind -n MouseDragEnd1Pane send-keys -M\nbind -n WheelUpPane send-keys -M\nbind -n WheelDownPane send-keys -M\nset-hook -g pane-exited 'if-shell -F \"#{==:#{hook_pane},%0}\" \"kill-session -t =workspace\"'\n")?;
        config.sync_all()?;
        let inner = shared.attach(false);
        let mut inner_text = String::from("unset TMUX TMUX_PANE; exec ");
        inner_text.push_str(&quote(inner.get_program())?);
        for arg in inner.get_args() {
            inner_text.push(' ');
            inner_text.push_str(&quote(arg)?);
        }
        let mut panel_text = String::from("exec ");
        panel_text.push_str(&quote(panel.get_program())?);
        for arg in panel.get_args() {
            panel_text.push(' ');
            panel_text.push_str(&quote(arg)?);
        }
        let mut command = self.local.command();
        command.args([
            "new-session",
            "-d",
            "-s",
            "workspace",
            "-x",
            &cols.to_string(),
            "-y",
            &rows.to_string(),
            &inner_text,
            ";",
            "split-window",
            "-h",
            "-l",
            "30",
            "-t",
            "%0",
            &panel_text,
            ";",
            "select-pane",
            "-t",
            "%0",
            ";",
            "attach-session",
            "-t",
            "=workspace",
        ]);
        Ok(command)
    }
    pub fn workspace(&self) -> &Workspace {
        &self.local
    }
}
impl Drop for OwnerView {
    fn drop(&mut self) {
        let _ = self.local.stop();
    }
}
