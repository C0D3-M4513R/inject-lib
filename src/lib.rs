//#![cfg_attr(feature = "nightly", feature(asm,global_asm, asm_const))]

use log::{debug, trace, warn};
use std::path::PathBuf;

pub struct Injector<'a> {
    pub dll: &'a str,
    pub pid: u32,
}

pub(crate) type Result<T> = std::result::Result<T, error::Error>;

pub mod error;
mod platforms;

impl<'a> Injector<'a> {
    pub fn new(dll: &'a str, pid: u32) -> Self {
        Injector { dll, pid }
    }
    pub fn set_dll(&mut self, dll: &'a str) {
        self.dll = dll;
    }
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }
}

impl<'a> Default for Injector<'a> {
    fn default() -> Self {
        Self::new("", 0)
    }
}
///This takes a string, and returns only the last path element
///Since this uses rust builtins, it should "just work".
pub fn strip_path(dll: &str) -> Result<String> {
    let pb = PathBuf::from(dll);
    match pb.file_name().and_then(|x| x.to_str()) {
        None => Err(error::Error::Io(std::io::Error::from(
            std::io::ErrorKind::Unsupported,
        ))),
        Some(v) => Ok(v.to_string()),
    }
}

///This truncates all 0 from the end of a Vec
///This will keep other 0 entries in the Vec perfectly intact.
///This has a worst case performance of o(n).
//todo: improve performance
pub fn trim_wide_str(mut v: Vec<u16>) -> Vec<u16> {
    while v.last().map(|x| *x) == Some(0) {
        v.pop();
    }
    return v;
}
