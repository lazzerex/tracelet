use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use tracelet_common::stream::{decode_stream, DashboardEvent, STREAM_MAX};

use crate::error::TraceletError;
use crate::events;
use crate::filter::{self, FilterArgs};
use crate::hist::Stats;
use crate::TraceletSkelBuilder;
use libbpf_rs::MapCore;

#[derive(Clone)]
pub struct StreamRow {
    pub wall: String,
    pub pid: u32,
    pub process: String,
    pub event: &'static str,
    pub details: String,
}

#[derive(Clone, Default)]
pub struct Overview {
    pub rate: u64,
    pub processes: usize,
    pub tcp_total: u64,
    pub file_total: u64,
    pub dropped: u64,
}

#[derive(Clone)]
pub struct TopRow {
    pub process: String,
    pub pid: u32,
    pub count: u64,
}

#[derive(Clone)]
pub struct Snapshot {
    pub overview: Overview,
    pub stream: Vec<StreamRow>,
    pub top: Vec<TopRow>,
    pub distribution: Vec<(String, u64)>,
    pub latency: Vec<(&'static str, Stats)>,
}

#[derive(Default)]
pub struct Shared {
    started: Option<std::time::Instant>,
    total: u64,
    tcp_total: u64,
    file_total: u64,
    dropped: u64,
    processes: HashMap<u32, (String, u64)>,
    by_event: HashMap<String, u64>,
    recent: std::collections::VecDeque<StreamRow>,
    latency: Vec<Vec<u64>>,
}

impl Shared {
    pub fn push(&mut self, ev: &DashboardEvent, wall: String) {
        self.total += 1;
        let comm = ev.comm();
        let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        let process = String::from_utf8_lossy(&comm[..end]).into_owned();
        let details = ev.details();
        let event_name = ev.event_name();
        let pid = ev.pid();
        match ev {
            DashboardEvent::Tcp { .. } => self.tcp_total += 1,
            DashboardEvent::File { .. } => self.file_total += 1,
        }
        let entry = self.processes.entry(pid).or_insert((process.clone(), 0));
        entry.1 += 1;
        if entry.0 != process {
            entry.0 = process.clone();
        }
        *self.by_event.entry(event_name.to_string()).or_insert(0) += 1;
        self.recent.push_back(StreamRow {
            wall,
            pid,
            process,
            event: event_name,
            details,
        });
        while self.recent.len() > STREAM_MAX {
            self.recent.pop_front();
        }
    }
}

fn wall_time(data: &[u8], boot_offset_ns: u64) -> String {
    if data.len() < 16 {
        return "???:??:??.???".into();
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&data[8..16]);
    crate::events::clock_time(boot_offset_ns.wrapping_add(u64::from_ne_bytes(raw)))
}

pub fn spawn(args: &FilterArgs, buffer_mb: u32) -> Result<Arc<Mutex<Shared>>, TraceletError> {
    crate::kernel::check_prereqs("dashboard")?;
    let config = filter::config(args, tracelet_common::FILTER_EVENT_ALL)?;
    let shared = Arc::new(Mutex::new(Shared::default()));
    init_shared(&shared);

    let thread_shared = Arc::clone(&shared);
    thread::spawn(move || {
        if let Err(err) = collect(&config, buffer_mb, thread_shared) {
            eprintln!("collector stopped: {err}");
        }
    });
    Ok(shared)
}

fn collect(
    config: &tracelet_common::FilterConfig,
    buffer_mb: u32,
    shared: Arc<Mutex<Shared>>,
) -> Result<(), TraceletError> {
    let skel_builder = TraceletSkelBuilder::default();
    let mut object = std::mem::MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut object)?;
    if buffer_mb != 16 {
        open_skel
            .maps
            .events
            .set_max_entries(buffer_mb * 1024 * 1024)?;
    }
    let skel = open_skel.load()?;
    filter::apply_map(&skel.maps.filter_map, config)?;

    let mut links = Vec::new();
    links.push(skel.progs.trace_exec.attach()?);
    for prog in [
        &skel.progs.trace_open,
        &skel.progs.trace_openat,
        &skel.progs.trace_openat2,
        &skel.progs.trace_tcp,
    ] {
        links.push(prog.attach()?);
    }
    let _links = links;

    let boot_offset_ns = events::boot_time_ns();

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| {
        if let Some(ev) = decode_stream(data) {
            let wall = wall_time(data, boot_offset_ns);
            if let Ok(mut guard) = shared.lock() {
                guard.push(&ev, wall);
            } else {
                eprintln!("warning: shared state poisoned; event ignored");
            }
        }
        0
    })?;
    let rb = rb_builder.build()?;

    let mut drops_seen = [0u64; 2];
    while crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        rb.poll(Duration::from_millis(200))?;
        let total = drops_seen[0] + drops_seen[1];
        if let Ok(mut guard) = shared.lock() {
            if total > guard.dropped {
                guard.dropped = total;
            }
        }
        let _ = crate::stats::warn_on_drops(&skel.maps.drops, &mut drops_seen);
        refresh_latency(&skel, &shared);
    }
    Ok(())
}

fn refresh_latency(skel: &crate::TraceletSkel<'_>, shared: &Arc<Mutex<Shared>>) {
    use tracelet_common::LATENCY_SLOTS;
    let mut histograms = Vec::new();
    for syscall in 0..tracelet_common::SYSCALL_COUNT {
        let mut slots = vec![0u64; LATENCY_SLOTS as usize];
        for (slot, count) in slots.iter_mut().enumerate() {
            let key = (syscall * LATENCY_SLOTS + slot as u32).to_ne_bytes();
            if let Ok(Some(value)) = skel
                .maps
                .latency_hist
                .lookup(&key, libbpf_rs::MapFlags::ANY)
            {
                if value.len() == 8 {
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&value[..8]);
                    *count = u64::from_ne_bytes(raw);
                }
            }
        }
        histograms.push(slots);
    }
    if let Ok(mut guard) = shared.lock() {
        guard.latency = histograms;
    } else {
        eprintln!("warning: shared state poisoned; latency snapshot skipped");
    }
}

pub fn collector_guard(shared: &Arc<Mutex<Shared>>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn init_shared(shared: &Arc<Mutex<Shared>>) {
    let mut guard = collector_guard(shared);
    if guard.started.is_none() {
        guard.started = Some(std::time::Instant::now());
    }
}

impl Snapshot {
    pub fn take(shared: &Shared) -> Snapshot {
        let secs = shared
            .started
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0)
            .max(1);
        let mut top: Vec<TopRow> = shared
            .processes
            .iter()
            .map(|(pid, (process, count))| TopRow {
                process: process.clone(),
                pid: *pid,
                count: *count,
            })
            .collect();
        top.sort_by(|a, b| b.count.cmp(&a.count).then(b.pid.cmp(&a.pid)));
        top.truncate(10);
        let mut distribution: Vec<(String, u64)> = shared
            .by_event
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect();
        distribution.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let latency = tracelet_common::SYSCALL_NAMES
            .iter()
            .zip(shared.latency.iter())
            .map(|(name, slots)| (*name, crate::hist::summarize(slots)))
            .collect();
        Snapshot {
            overview: Overview {
                rate: shared.total / secs,
                processes: shared.processes.len(),
                tcp_total: shared.tcp_total,
                file_total: shared.file_total,
                dropped: shared.dropped,
            },
            stream: shared.recent.iter().rev().cloned().collect(),
            top,
            distribution,
            latency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Shared, Snapshot};
    use tracelet_common::stream::{DashboardEvent, FILE_EVENT_EXEC, FILE_EVENT_OPEN, STREAM_MAX};

    fn file_event(kind: u8, pid: u32, comm: &[u8]) -> DashboardEvent {
        let mut c = [0u8; 16];
        c[..comm.len()].copy_from_slice(comm);
        DashboardEvent::File {
            pid,
            ppid: 1,
            kind,
            comm: c,
            path: [0u8; 128],
        }
    }

    fn tcp_event(pid: u32, comm: &[u8]) -> DashboardEvent {
        let mut c = [0u8; 16];
        c[..comm.len()].copy_from_slice(comm);
        DashboardEvent::Tcp {
            pid,
            event_type: 1,
            family: 2,
            comm: c,
            dest: "10.0.0.1:443".to_string(),
        }
    }

    #[test]
    fn push_updates_totals_top_and_distribution() {
        let mut shared = Shared::default();
        shared.push(&file_event(FILE_EVENT_EXEC, 1, b"bash"), "t1".into());
        shared.push(&file_event(FILE_EVENT_OPEN, 1, b"bash"), "t2".into());
        shared.push(&tcp_event(2, b"curl"), "t3".into());

        let snap = Snapshot::take(&shared);
        assert_eq!(snap.overview.file_total, 2);
        assert_eq!(snap.overview.tcp_total, 1);
        assert_eq!(snap.overview.processes, 2);
        assert_eq!(snap.top.len(), 2);
        assert_eq!(snap.top[0].count, 2);
        assert_eq!(snap.top[0].process, "bash");
        assert_eq!(
            snap.distribution,
            vec![
                ("CONNECT".to_string(), 1),
                ("EXEC".to_string(), 1),
                ("OPEN".to_string(), 1)
            ]
        );
    }

    #[test]
    fn stream_is_newest_first_and_capped() {
        let mut shared = Shared::default();
        for i in 0..(STREAM_MAX + 5) {
            shared.push(&file_event(FILE_EVENT_EXEC, i as u32, b"p"), "t".into());
        }
        let snap = Snapshot::take(&shared);
        assert_eq!(snap.stream.len(), STREAM_MAX);
        assert_eq!(snap.stream[0].pid, (STREAM_MAX + 4) as u32);
        assert_eq!(snap.stream.last().unwrap().pid, 5);
    }

    #[test]
    fn rate_divides_total_by_elapsed_seconds() {
        let mut shared = Shared {
            started: Some(std::time::Instant::now()),
            ..Shared::default()
        };
        shared.push(&file_event(FILE_EVENT_EXEC, 1, b"x"), "t".into());
        shared.push(&file_event(FILE_EVENT_EXEC, 2, b"x"), "t".into());
        shared.push(&tcp_event(3, b"x"), "t".into());
        let snap = Snapshot::take(&shared);
        assert_eq!(snap.overview.rate, 3);
    }

    #[test]
    fn process_name_updates_in_place() {
        let mut shared = Shared::default();
        shared.push(&file_event(FILE_EVENT_EXEC, 1, b"old"), "t".into());
        shared.push(&file_event(FILE_EVENT_EXEC, 1, b"new"), "t".into());
        let snap = Snapshot::take(&shared);
        assert_eq!(snap.overview.processes, 1);
        assert_eq!(snap.top[0].process, "new");
        assert_eq!(snap.top[0].count, 2);
    }
}
