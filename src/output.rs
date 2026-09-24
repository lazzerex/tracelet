use std::io::Write;

fn json_escape_string(out: &mut String, s: &str) {
    out.push('"');
    for b in s.bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                out.push_str("\\u00");
                out.push_str(&format!("{b:02x}"));
            }
        }
    }
    out.push('"');
}

pub fn exec_json_line(
    out: &mut String,
    time: &str,
    pid: u32,
    ppid: u32,
    comm: &str,
    filename: &str,
) {
    out.push_str("{\"event\":\"exec\",\"time\":");
    json_escape_string(out, time);
    out.push_str(",\"pid\":");
    out.push_str(&pid.to_string());
    out.push_str(",\"ppid\":");
    out.push_str(&ppid.to_string());
    out.push_str(",\"comm\":");
    json_escape_string(out, comm);
    out.push_str(",\"filename\":");
    json_escape_string(out, filename);
    out.push_str("}\n");
}

pub fn open_json_line(out: &mut String, time: &str, pid: u32, comm: &str, filename: &str) {
    out.push_str("{\"event\":\"open\",\"time\":");
    json_escape_string(out, time);
    out.push_str(",\"pid\":");
    out.push_str(&pid.to_string());
    out.push_str(",\"comm\":");
    json_escape_string(out, comm);
    out.push_str(",\"filename\":");
    json_escape_string(out, filename);
    out.push_str("}\n");
}

pub fn tcp_json_line(
    out: &mut String,
    time: &str,
    pid: u32,
    comm: &str,
    event: &str,
    source: &str,
    destination: &str,
) {
    out.push_str("{\"event\":\"tcp\",\"time\":");
    json_escape_string(out, time);
    out.push_str(",\"pid\":");
    out.push_str(&pid.to_string());
    out.push_str(",\"comm\":");
    json_escape_string(out, comm);
    out.push_str(",\"tcp_event\":");
    json_escape_string(out, event);
    out.push_str(",\"source\":");
    json_escape_string(out, source);
    out.push_str(",\"destination\":");
    json_escape_string(out, destination);
    out.push_str("}\n");
}

pub fn latency_json_line(
    out: &mut String,
    time: &str,
    syscall: &str,
    count: u64,
    p50: &str,
    p95: &str,
    p99: &str,
) {
    out.push_str("{\"event\":\"latency\",\"time\":");
    json_escape_string(out, time);
    out.push_str(",\"syscall\":");
    json_escape_string(out, syscall);
    out.push_str(",\"count\":");
    out.push_str(&count.to_string());
    out.push_str(",\"p50\":");
    json_escape_string(out, p50);
    out.push_str(",\"p95\":");
    json_escape_string(out, p95);
    out.push_str(",\"p99\":");
    json_escape_string(out, p99);
    out.push_str("}\n");
}

pub fn write_all(buf: &str) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(buf.as_bytes());
}

pub fn print_summary(printed: u64, dropped: u64, elapsed: std::time::Duration) {
    eprintln!(
        "stopped: {} events printed, {} dropped, {:.1}s elapsed",
        printed,
        dropped,
        elapsed.as_secs_f64()
    );
}

#[cfg(test)]
mod tests {
    use super::json_escape_string;

    #[test]
    fn escapes_quotes_and_backslashes() {
        let mut s = String::new();
        json_escape_string(&mut s, r#"a"b\c"#);
        assert_eq!(s, r#""a\"b\\c""#);
    }

    #[test]
    fn escapes_control_characters() {
        let mut s = String::new();
        json_escape_string(&mut s, "a\nb\tc");
        assert_eq!(s, r#""a\nb\tc""#);
    }

    #[test]
    fn handles_empty_string() {
        let mut s = String::new();
        json_escape_string(&mut s, "");
        assert_eq!(s, "\"\"");
    }

    #[test]
    fn handles_127_byte_path() {
        let path = "/".repeat(127);
        let mut s = String::new();
        json_escape_string(&mut s, &path);
        assert_eq!(s.len(), 127 + 2);
        assert!(s.starts_with('"'));
        assert!(s.ends_with('"'));
    }

    #[test]
    fn handles_non_ascii_bytes() {
        let mut s = String::new();
        json_escape_string(&mut s, "\x00\u{ff}");
        assert_eq!(s, "\"\\u0000\\u00c3\\u00bf\"");
    }
}
