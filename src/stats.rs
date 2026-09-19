use libbpf_rs::{MapCore, MapFlags, MapMut};

use crate::error::TraceletError;

const DROPS_KEY: u32 = 0;

pub fn dropped_events(map: &MapMut<'_>) -> Result<u64, TraceletError> {
    let key = DROPS_KEY.to_ne_bytes();
    match map.lookup(&key, MapFlags::ANY)? {
        Some(value) if value.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&value[..8]);
            Ok(u64::from_ne_bytes(raw))
        }
        _ => Ok(0),
    }
}

pub fn warn_on_drops(map: &MapMut<'_>, seen: &mut u64) -> Result<(), TraceletError> {
    let dropped = dropped_events(map)?;
    if dropped > *seen {
        eprintln!("warning: {dropped} events dropped by the kernel");
        *seen = dropped;
    }
    Ok(())
}
