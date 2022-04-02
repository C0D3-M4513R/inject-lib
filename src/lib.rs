//#![cfg_attr(feature = "nightly", feature(asm,global_asm, asm_const))]

extern crate core;

use log::{debug, trace, warn};
use std::path::PathBuf;
///This struct will expose certain module private functions, to actually use the api.
#[derive(Debug, Clone)]
pub struct Injector<'a> {
    pub dll: &'a str,
    pub pid: u32,
}

pub(crate) type Result<T> = std::result::Result<T, error::Error>;

pub mod error;
mod platforms;

impl<'a> Injector<'a> {
    ///Create a new Injector object.
    pub fn new(dll: &'a str, pid: u32) -> Self {
        Injector { dll, pid }
    }
    ///Sets the dll
    pub fn set_dll(&mut self, dll: &'a str) {
        self.dll = dll;
    }
    ///Sets the pid
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

#[cfg(test)]
mod test {
    ///This string contains a bunch of special chars, to test methods operating on strings.
    pub const str:&str = "This is just any string, since we are not testing anything else, other than setting the dll.!'\r\n\t%$§\"{\\[()]}=?´`öäü^°,.-;:_#+*~<>|³²@";

    use crate::Result;
    #[test]
    fn trim_vec() {
        let buf: Vec<u16> = (0..u16::MAX).collect();
        let mut buf2 = buf.clone();
        buf2.append(&mut [0u16; 100].to_vec());

        assert_eq!(super::trim_wide_str(buf2), buf);
    }

    #[test]
    fn strip_path() -> Result<()> {
        assert_eq!(
            super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end\\")?,
            "end",
            "strip path failed to strip the end of a win path, with a dir at the end"
        );
        assert_eq!(
            super::strip_path("C:/this/is/a/test/path/with/a/dir/at/the/end/")?,
            "end",
            "strip path failed to strip the end of a rust path, with a dir at the end"
        );
        assert_eq!(super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end")?,"end","strip path failed to strip the end of a win path, with a dir/extensionless file at the end");
        assert_eq!(super::strip_path("C:/this/is/a/test/path/with/a/dir/at/the/end")?,"end","strip path failed to strip the end of a rust path, with a dir/extensionless file at the end");
        assert_eq!(
            super::strip_path(
                "C:\\this\\is\\a\\test\\path\\with\\a\\file\\at\\the\\end\\file.txt"
            )?,
            "file.txt",
            "strip path failed to strip the end of a win path, with a file at the end"
        );
        assert_eq!(
            super::strip_path("C:/this/is/a/test/path/with/a/file/at/the/end/file.txt")?,
            "file.txt",
            "strip path failed to strip the end of a rust path, with a file at the end"
        );
        Ok(())
    }
    #[test]
    fn set_dll() {
        let mut inj = super::Injector::default();
        inj.set_dll(str);
        assert_eq!(inj.dll, str, "Setter did not correctly set the dll string");
    }
    #[test]
    fn set_pid() {
        let mut inj = super::Injector::default();
        const pid: u32 = 0;
        inj.set_pid(pid);
        assert_eq!(inj.pid, pid, "Setter did not correctly set the pid");
    }
}
