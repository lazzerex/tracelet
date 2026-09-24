use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

pub fn parse_buffer_mb(s: &str) -> Result<u32, String> {
    let mb: u32 = s
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    if mb == 0 || !mb.is_power_of_two() {
        return Err("must be a power of 2 (1, 2, 4, 8, 16, ...)".into());
    }
    Ok(mb)
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("ms") {
        n.parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>()
            .map(|v| Duration::from_secs(v * 60))
            .map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>()
            .map(|v| Duration::from_secs(v * 3600))
            .map_err(|e| e.to_string())
    } else {
        Err(format!("invalid duration '{s}': use Ns, Nm, Nms, or Nh"))
    }
}

mod collector;
mod dashboard;
mod error;
mod events;
mod exec;
mod filter;
mod hist;
mod kernel;
mod latency;
mod open;
mod output;
mod stats;
mod tcp;

pub use error::TraceletError;
use filter::{EventKind, FilterArgs, SyscallKind};

include!(concat!(env!("OUT_DIR"), "/tracelet.skel.rs"));

pub static RUNNING: AtomicBool = AtomicBool::new(true);

pub const EXIT_OK: i32 = 0;
pub const EXIT_RUNTIME: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Parser)]
#[command(name = "tracelet", version, about = "Linux observability with eBPF")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(clap::Args, Clone, Copy)]
pub struct BufferArgs {
    #[arg(long, default_value_t = 16, value_parser = parse_buffer_mb, value_name = "MB", help = "Ring buffer size in MiB (power of 2, minimum 1)")]
    pub buffer_mb: u32,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Trace process execution events")]
    Exec {
        #[command(flatten)]
        filter: FilterArgs,
        #[command(flatten)]
        buffer: BufferArgs,
        #[arg(long, help = "Stop after N printed events")]
        count: Option<u64>,
        #[arg(long, value_parser = parse_duration, value_name = "DURATION", help = "Stop after this duration (e.g. 30s, 5m)")]
        duration: Option<Duration>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
        json: OutputFormat,
    },
    #[command(about = "Trace file open events")]
    Open {
        #[command(flatten)]
        filter: FilterArgs,
        #[command(flatten)]
        buffer: BufferArgs,
        #[arg(long, help = "Stop after N printed events")]
        count: Option<u64>,
        #[arg(long, value_parser = parse_duration, value_name = "DURATION", help = "Stop after this duration (e.g. 30s, 5m)")]
        duration: Option<Duration>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
        json: OutputFormat,
    },
    #[command(about = "Trace TCP connection events")]
    Tcp {
        #[command(flatten)]
        filter: FilterArgs,
        #[command(flatten)]
        buffer: BufferArgs,
        #[arg(long, value_enum, help = "Only show this connection event")]
        event: Option<EventKind>,
        #[arg(long, help = "Stop after N printed events")]
        count: Option<u64>,
        #[arg(long, value_parser = parse_duration, value_name = "DURATION", help = "Stop after this duration (e.g. 30s, 5m)")]
        duration: Option<Duration>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
        json: OutputFormat,
    },
    #[command(about = "Measure event latency statistics")]
    Latency {
        #[command(flatten)]
        filter: FilterArgs,
        #[command(flatten)]
        buffer: BufferArgs,
        #[arg(long, value_enum, help = "Only measure this syscall")]
        syscall: Option<SyscallKind>,
        #[arg(long, value_parser = parse_duration, value_name = "DURATION", help = "Stop after this duration (e.g. 30s, 5m)")]
        duration: Option<Duration>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
        json: OutputFormat,
    },
    #[command(about = "Launch the terminal dashboard", after_help = DASHBOARD_HELP)]
    Dashboard {
        #[command(flatten)]
        filter: FilterArgs,
        #[command(flatten)]
        buffer: BufferArgs,
    },
}

const DASHBOARD_HELP: &str = "Keys:\n  space   pause / resume\n  up/down scroll one row\n  pgup/pgdn scroll a page\n  home    newest event\n  end     oldest event\n  tab     switch pane\n  q       quit";

fn install_signal_handler() {
    unsafe {
        libc::sigaction(
            libc::SIGINT,
            &libc::sigaction {
                sa_sigaction: signal_handler as *const () as usize,
                sa_mask: std::mem::zeroed(),
                sa_flags: 0,
                sa_restorer: None,
            },
            std::ptr::null_mut(),
        );
        libc::sigaction(
            libc::SIGTERM,
            &libc::sigaction {
                sa_sigaction: signal_handler as *const () as usize,
                sa_mask: std::mem::zeroed(),
                sa_flags: 0,
                sa_restorer: None,
            },
            std::ptr::null_mut(),
        );
    }
}

extern "C" fn signal_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn should_stop(
    count_printed: u64,
    count_limit: Option<u64>,
    start: std::time::Instant,
    duration_limit: Option<Duration>,
) -> bool {
    if !RUNNING.load(Ordering::SeqCst) {
        return true;
    }
    if let Some(max) = count_limit {
        if count_printed >= max {
            return true;
        }
    }
    if let Some(dur) = duration_limit {
        if start.elapsed() >= dur {
            return true;
        }
    }
    false
}

pub fn main() -> Result<(), TraceletError> {
    let cli = Cli::parse();
    install_signal_handler();
    match &cli.command {
        Command::Exec {
            filter,
            buffer,
            count,
            duration,
            json,
        } => exec::run(filter, buffer.buffer_mb, *count, *duration, *json)?,
        Command::Open {
            filter,
            buffer,
            count,
            duration,
            json,
        } => open::run(filter, buffer.buffer_mb, *count, *duration, *json)?,
        Command::Tcp {
            filter,
            buffer,
            event,
            count,
            duration,
            json,
        } => tcp::run(filter, buffer.buffer_mb, *event, *count, *duration, *json)?,
        Command::Latency {
            filter,
            buffer,
            syscall,
            duration,
            json,
        } => latency::run(filter, buffer.buffer_mb, *syscall, *duration, *json)?,
        Command::Dashboard { filter, buffer } => dashboard::run(filter, buffer.buffer_mb)?,
    }
    Ok(())
}
