use std::fmt;

#[derive(Debug)]
pub enum TraceletError {
    Bpf(String),
    Io(std::io::Error),
}

impl fmt::Display for TraceletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceletError::Bpf(msg) => write!(f, "bpf error: {msg}"),
            TraceletError::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for TraceletError {}

impl From<std::io::Error> for TraceletError {
    fn from(err: std::io::Error) -> Self {
        TraceletError::Io(err)
    }
}
