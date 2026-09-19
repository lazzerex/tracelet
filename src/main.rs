use clap::{Parser, Subcommand};

mod error;
mod events;
mod exec;
mod filter;
mod hist;
mod latency;
mod open;
mod stats;
mod tcp;

pub use error::TraceletError;
use filter::{EventKind, FilterArgs, SyscallKind};

include!(concat!(env!("OUT_DIR"), "/tracelet.skel.rs"));

#[derive(Parser)]
#[command(name = "tracelet", version, about = "Linux observability with eBPF")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Trace process execution events")]
    Exec {
        #[command(flatten)]
        filter: FilterArgs,
    },
    #[command(about = "Trace file open events")]
    Open {
        #[command(flatten)]
        filter: FilterArgs,
    },
    #[command(about = "Trace TCP connection events")]
    Tcp {
        #[command(flatten)]
        filter: FilterArgs,
        #[arg(long, value_enum, help = "Only show this connection event")]
        event: Option<EventKind>,
    },
    #[command(about = "Measure event latency statistics")]
    Latency {
        #[command(flatten)]
        filter: FilterArgs,
        #[arg(long, value_enum, help = "Only measure this syscall")]
        syscall: Option<SyscallKind>,
    },
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
        Command::Exec { filter } => exec::run(filter)?,
        Command::Open { filter } => open::run(filter)?,
        Command::Tcp { filter, event } => tcp::run(filter, *event)?,
        Command::Latency { filter, syscall } => latency::run(filter, *syscall)?,
        Command::Top => placeholder("top"),
        Command::Dashboard => placeholder("dashboard"),
    }
    Ok(())
}
