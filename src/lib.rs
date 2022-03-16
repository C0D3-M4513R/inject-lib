// #![cfg_attr(feature = "nightly", feature(asm,global_asm, asm_const))]

use log::{debug, error, trace, warn};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub struct Injector<'a> {
    pub dll: &'a str,
    pub pid: u32,
}

pub(crate) type Result<T> = std::result::Result<T, error::Error>;

pub mod error;
mod hof;
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
    pub fn find_pid(name: &str) -> Result<Vec<u32>> {
        Self::find_pid_selector(|p| {
            match crate::str_from_wide_str(crate::trim_wide_str(p.szExeFile.to_vec()).as_slice()) {
                Ok(str) => {
                    debug!("Checking {} against {}", str, name);
                    strip_rust_path(str.as_str()) == name
                }
                Err(e) => {
                    warn!("Skipping check of process. Can't construct string, to compare against. Err:{:#?}",e);
                    false
                }
            }
        })
    }
}

impl<'a> Default for Injector<'a> {
    fn default() -> Self {
        Self::new("", 0)
    }
}
///This takes a string, and cuts off, everything before the last `/`.
/// The intention is, that this will truncate any rust(/Linux?) path (since rust uses `/`), to it's filename, without having to actually look the file up.
pub fn strip_rust_path(str: &str) -> &str {
    let mut str_no_path = str;

    if let Some(n) = str.rfind('/') {
        //I do n+1 here, since, the rfind will actually keep the last /.
        //This gets rid of the /
        str_no_path = str.get((n + 1)..).unwrap();
    }
    debug!("str='{}' and truncated='{}'", str, str_no_path);
    str_no_path
}
///This takes a string, and cuts off, everything before the last `\`.
/// The intention is, that this will truncate any windows path (since windows uses `\`), to it's filename, without having to actually look the file up.
pub fn strip_win_path(str: &str) -> &str {
    let mut str_no_path = str;

    if let Some(n) = str.rfind('\\') {
        //I do n+1 here, since, the rfind will actually keep the last /.
        //This gets rid of the /
        str_no_path = str.get((n + 1)..).unwrap();
    }
    trace!("str='{}' and truncated='{}'", str, str_no_path);
    str_no_path
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

pub fn str_from_wide_str(v: &[u16]) -> Result<String> {
    OsString::from_wide(v).into_string().map_err(|e| {
        warn!("Couldn't convert widestring, to string. The Buffer contained invalid non-UTF-8 characters . Buf is {:#?}.", e);
        error::Error::WTFConvert(e)
    })
}
