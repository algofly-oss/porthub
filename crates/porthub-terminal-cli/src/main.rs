use clap::Parser;

#[derive(Parser)]
#[command(version = porthub_terminal_cli::VERSION, about = "PortHub custom terminal access has been removed")]
struct Args {}

fn main() -> std::process::ExitCode {
    Args::parse();
    eprintln!("PortHub custom terminal access has been removed.");
    std::process::ExitCode::FAILURE
}
