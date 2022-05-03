//!This Crate Provides functionality, for injecting dlls into other processes.
//!Most of the crate is right now accessible through the [Injector] class.
//!
//!You will need to provide a pid, and a dll to inject. This crate will do the rest for you.
//!
//! The main focus will always be on performing the injection reliable.
//! If you care about injecting into a 64 bit application whilst needing to compile this library under 32 bits, you will want to enable the "x86tox64" feature.
//! Be aware, that that feature uses "unofficial" api's located in ntdll.dll.
//! Compatibility is technically not guaranteed by windows.
//!
//!If you have any suggestions, on improving the outfacing api of this crate create an issue, or pr.
//!I am not sure yet, if I like this design.
//!
//!Linux support will probably not come.
//!It is insanely hard and platform specific, because
//! 1. we would need to write raw machinecode/shellcode to the target process.
//! 3. which then has the necessary code to load the .so
//! 4. we need to somehow redirect the target program's execution, to execute our code
//! 5. we need to do that, without somehow disrupting ANY of the program's code
//! 6. we need to return the EXACT state before we did anything, because the other program may need that
//!
//! If this library is supposed to be helpful I'd want to not require to run it as root.
//! Unfortunately some steps involve calling ptrace. Access to the command is restricted, if you are not the parent process of the process you are trying to trace.
//! These requirements would mean, that we can only inject so files to processes, that the program this library itself created.
// #![feature(strict_provenance)]
// #![warn(lossy_provenance_casts)]
#![warn(missing_docs)]

///This struct will expose certain module private functions, to actually use the api.
///The exact contents should be considered implementation detail.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Injector<'a> {
    ///The path to a dll. This may be in any format, that rust understands
    pub dll: &'a str,
    ///The pid the dll should be injected into
    pub pid: u32,
}

pub(crate) type Result<T> = std::result::Result<T, error::Error>;
pub(crate) use log::{debug, error, info, trace, warn};
use std::path::{Path, PathBuf};

///Holds all error types
pub mod error;
mod platforms;
///This represents the actions, that are supported with a dll.
pub trait Inject {
    ///Injects a dll
    fn inject(&self) -> Result<()>;
    ///Ejects a dll
    fn eject(&self) -> Result<()>;
    ///This Function will find all currently processes, with a given name.
    ///Even if no processes are found, an empty Vector should return.
    fn find_pid<P: AsRef<Path>>(name: P) -> Result<Vec<u32>>;
}

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
    #[cfg(target_family = "windows")]
    ///Gets the Platform specific Injector.
    ///Currently only windows is supported.
    ///wait indicates, if we should wait on the dll to attach to the process
    pub fn inject(&self, wait: bool) -> impl Inject + '_ {
        platforms::windows::InjectWin { inj: self, wait }
    }
    #[cfg(target_family = "windows")]
    ///This Function will find all currently processes, with a given name.
    ///Even if no processes are found, an empty Vector should return.
    pub fn find_pid<P: AsRef<Path>>(name: P) -> Result<Vec<u32>> {
        platforms::windows::InjectWin::find_pid(name)
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
