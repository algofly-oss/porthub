use std::process::Command;

#[test]
fn helper_rejects_shells_and_internal_worker_entry_points() {
    for command in [
        "terminal",
        "join",
        "tmux",
        "__serve",
        "__porthub-worker",
        "__porthub-stdio",
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_porthub-terminal"))
            .arg(command)
            .output()
            .unwrap()
            .status;
        assert!(!status.success(), "accepted {command}");
    }
}
