use std::fmt;

#[derive(Debug)]
pub enum TraceletError {
    Bpf(String),
    Io(std::io::Error),
    Libbpf(libbpf_rs::Error),
}

impl fmt::Display for TraceletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceletError::Bpf(msg) => write!(f, "bpf error: {msg}"),
            TraceletError::Io(err) => write!(f, "io error: {err}"),
            TraceletError::Libbpf(err) => write!(f, "libbpf error: {err}"),
        }
    }
}

impl std::error::Error for TraceletError {}

impl From<std::io::Error> for TraceletError {
    fn from(err: std::io::Error) -> Self {
        TraceletError::Io(err)
    }
}

impl From<libbpf_rs::Error> for TraceletError {
    fn from(err: libbpf_rs::Error) -> Self {
        TraceletError::Libbpf(err)
    }
}
