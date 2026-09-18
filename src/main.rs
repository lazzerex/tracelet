use clap::{Parser, Subcommand};

mod error;

pub use error::TraceletError;

#[derive(Parser)]
#[command(name = "tracelet", version, about = "Linux observability with eBPF")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Trace process execution events")]
    Exec,
    #[command(about = "Trace file open events")]
    Open,
    #[command(about = "Trace TCP connection events")]
    Tcp,
    #[command(about = "Measure event latency statistics")]
    Latency,
    #[command(about = "Show live top-style view of activity")]
    Top,
    #[command(about = "Launch the terminal dashboard")]
    Dashboard,
}

fn placeholder(name: &str) {
    println!("{name}: not implemented yet");
}

fn main() -> Result<(), TraceletError> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Exec => placeholder("exec"),
        Command::Open => placeholder("open"),
        Command::Tcp => placeholder("tcp"),
        Command::Latency => placeholder("latency"),
        Command::Top => placeholder("top"),
        Command::Dashboard => placeholder("dashboard"),
    }
    Ok(())
}
