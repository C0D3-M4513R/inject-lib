#![warn(missing_docs)]
///This Crate Provides functionality, for injecting dlls into other processes.
///Most of the crate is right now accessible through the [Injector] class.
///
///You will need to provide a pid, and a dll to inject. This crate will do the rest for you.
///
///The main focus will always be on performing the injection reliable.
///
///If you have any suggestions, on improving the outfacing api of this crate create an issue, or pr.
///I am not sure yet, if I like this design.
///
///Linux support may come, but I am unsure if I will get to it. (and how easy it will be).

///This struct will expose certain module private functions, to actually use the api.
#[derive(Debug, Clone)]
pub struct Injector<'a> {
    ///The path to a dll. This may be in any format, that rust understands
    pub dll: &'a str,
    ///The pid the dll should be injected into
    pub pid: u32,
}

pub(crate) type Result<T> = std::result::Result<T, error::Error>;
pub(crate) use log::{debug, error, info, trace, warn};
use std::path::PathBuf;

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
    pub const STR:&str = "This is just any string, since we are not testing anything else, other than setting the dll.!'\r\n\t%$§\"{\\[()]}=?´`öäü^°,.-;:_#+*~<>|³²@";

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
        #[cfg(target_family = "windows")]
        assert_eq!(
            super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end\\")?,
            "end",
            "strip path failed to strip the end of a win path, with a dir at the end"
        );
        assert_eq!(
            super::strip_path("/this/is/a/test/path/with/a/dir/at/the/end/")?,
            "end",
            "strip path failed to strip the end of a rust path, with a dir at the end"
        );
        #[cfg(target_family = "windows")]
        assert_eq!(super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end")?,"end","strip path failed to strip the end of a win path, with a dir/extensionless file at the end");
        assert_eq!(super::strip_path("/this/is/a/test/path/with/a/dir/at/the/end")?,"end","strip path failed to strip the end of a rust path, with a dir/extensionless file at the end");
        #[cfg(target_family = "windows")]
        assert_eq!(
            super::strip_path(
                "C:\\this\\is\\a\\test\\path\\with\\a\\file\\at\\the\\end\\file.txt"
            )?,
            "file.txt",
            "strip path failed to strip the end of a win path, with a file at the end"
        );
        assert_eq!(
            super::strip_path("/this/is/a/test/path/with/a/file/at/the/end/file.txt")?,
            "file.txt",
            "strip path failed to strip the end of a rust path, with a file at the end"
        );
        Ok(())
    }
    #[test]
    fn set_dll() {
        let mut inj = super::Injector::default();
        inj.set_dll(STR);
        assert_eq!(inj.dll, STR, "Setter did not correctly set the dll string");
    }
    #[test]
    fn set_pid() {
        let mut inj = super::Injector::default();
        const PID: u32 = 0;
        inj.set_pid(PID);
        assert_eq!(inj.pid, PID, "Setter did not correctly set the PID");
    }
}
