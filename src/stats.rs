use libbpf_rs::{MapCore, MapFlags, MapMut};

use crate::error::TraceletError;

fn read_drop_key(map: &MapMut<'_>, key: u32) -> Result<u64, TraceletError> {
    let key = key.to_ne_bytes();
    match map.lookup(&key, MapFlags::ANY)? {
        Some(value) if value.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&value[..8]);
            Ok(u64::from_ne_bytes(raw))
        }
        _ => Ok(0),
    }
}

pub fn warn_on_drops(map: &MapMut<'_>, seen: &mut [u64; 2]) -> Result<(), TraceletError> {
    let ringbuf = read_drop_key(map, 0)?;
    let latency = read_drop_key(map, 1)?;
    if ringbuf > seen[0] {
        eprintln!("warning: {ringbuf} ring-buffer drops");
        seen[0] = ringbuf;
    }
    if latency > seen[1] {
        eprintln!("warning: {latency} latency-map drops");
        seen[1] = latency;
    }
    Ok(())
}
