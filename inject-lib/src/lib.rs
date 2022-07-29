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
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(not(feature = "alloc"))]
compile_error!("inject_lib doesn't yet support no alloc environments");
extern crate core;

use alloc::vec::Vec;

///This struct will expose certain module private functions, to actually use the api.
///The exact contents should be considered implementation detail.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Injector<'a> {
    ///The path to a dll. This may be in any format, that rust understands
    pub dll: Data<'a>,
    ///The pid the dll should be injected into
    pub pid: u32,
}

pub(crate) type Result<T, V = error::Error> = core::result::Result<T, V>;
pub(crate) use log::{debug, error, info, trace, warn};

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
    fn find_pid(name: Data) -> Result<Vec<u32>>;
}
///Data can be a Path(if we have std), or a String.
///Data will get handled differently in no_std and std scenarios
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Data<'a> {
    ///This a Path as a String
    Str(&'a str),
    ///This is a Path encoded as a Path std object
    #[cfg(feature = "std")]
    Path(&'a std::path::Path),
}
impl<'a> Data<'a> {
    fn get_str(&self) -> Option<&'a str> {
        match self {
            Data::Str(a) => Some(a),
            _ => None,
        }
    }
    #[cfg(feature = "std")]
    fn get_path(&self) -> Option<&'a std::path::Path> {
        match self {
            Data::Path(a) => Some(a),
            _ => None,
        }
    }
}

impl<'a> Injector<'a> {
    ///Create a new Injector object.
    pub fn new(dll: Data<'a>, pid: u32) -> Self {
        Injector { dll, pid }
    }
    ///Sets the dll
    pub fn set_dll(&mut self, dll: Data<'a>) {
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
    pub fn find_pid(name: Data) -> Result<Vec<u32>> {
        platforms::windows::InjectWin::find_pid(name)
    }
}

impl<'a> Default for Injector<'a> {
    fn default() -> Self {
        Self::new(crate::Data::Str(""), 0)
    }
}
// #[cfg(feature = "std")]
// ///This takes a string, and returns only the last path element
// ///Since this uses rust builtins, it should "just work".
// pub fn strip_path(dll: &str) -> Result<String> {
//     let pb = std::path::PathBuf::from(dll);
//     match pb.file_name().and_then(|x| x.to_str()) {
//         None => Err(error::Error::Io(std::io::Error::from(
//             std::io::ErrorKind::Unsupported,
//         ))),
//         Some(v) => Ok(v.to_string()),
//     }
// }

///This truncates all 0 from the end of a Vec
///This will keep other 0 entries in the Vec perfectly intact.
///This has a worst case performance of o(n).
///if fast==true, the data MUST only contain NULL-values at the end of the string O(log n)
///else O(n)
pub fn trim_wide_str<const FAST: bool>(v: &[u16]) -> &[u16] {
    let i = {
        if FAST {
            v.partition_point(|x| *x != 0)
        } else {
            let mut len = v.len();
            while v[len - 1] == 0 {
                len -= 1;
            }
            len
        }
    };
    let (out, _) = v.split_at(i);
    return out;
}

///Returns a function, which compares [crate::Data] against some other [crate::Data].
///If in no_std enviromenmt, the comparison is affected by forward-slash vs back-slash
//todo: make the second function call better
fn cmp<'a>(name: crate::Data<'a>) -> impl Fn(crate::Data<'_>) -> bool + 'a {
    move |s| {
        return match name {
            crate::Data::Str(s2) => match s {
                crate::Data::Str(s) => s2.ends_with(s) || s.ends_with(s2),
                #[cfg(feature = "std")]
                crate::Data::Path(p) => {
                    let p1 = std::path::Path::new(s2);
                    p1.ends_with(p) || p.ends_with(p1)
                }
            },
            #[cfg(feature = "std")]
            crate::Data::Path(p2) => match s {
                crate::Data::Str(s) => {
                    let p1 = std::path::Path::new(s);
                    p1.ends_with(p2) || p2.ends_with(p1)
                }
                #[cfg(feature = "std")]
                crate::Data::Path(p) => p.ends_with(p2) || p2.ends_with(p),
            },
        };
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;
    ///This string contains a bunch of special chars, to test methods operating on strings.
    pub const STR:&str = "This is just any string, since we are not testing anything else, other than setting the dll.!'\r\n\t%$§\"{\\[()]}=?´`öäü^°,.-;:_#+*~<>|³²@";

    use crate::Result;
    #[test]
    fn trim_vec() {
        let buf: Vec<u16> = (1..u16::MAX).collect();
        let mut buf2 = buf.clone();
        buf2.append(&mut [0u16; 100].to_vec());

        assert_eq!(super::trim_wide_str::<true>(buf2.as_slice()), buf);
        assert_eq!(super::trim_wide_str::<false>(buf2.as_slice()), buf);
    }

    // #[test]
    // fn strip_path() -> Result<()> {
    //     #[cfg(target_family = "windows")]
    //     assert_eq!(
    //         super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end\\")?,
    //         "end",
    //         "strip path failed to strip the end of a win path, with a dir at the end"
    //     );
    //     assert_eq!(
    //         super::strip_path("/this/is/a/test/path/with/a/dir/at/the/end/")?,
    //         "end",
    //         "strip path failed to strip the end of a rust path, with a dir at the end"
    //     );
    //     #[cfg(target_family = "windows")]
    //     assert_eq!(super::strip_path("C:\\this\\is\\a\\test\\path\\with\\a\\dir\\at\\the\\end")?,"end","strip path failed to strip the end of a win path, with a dir/extensionless file at the end");
    //     assert_eq!(super::strip_path("/this/is/a/test/path/with/a/dir/at/the/end")?,"end","strip path failed to strip the end of a rust path, with a dir/extensionless file at the end");
    //     #[cfg(target_family = "windows")]
    //     assert_eq!(
    //         super::strip_path(
    //             "C:\\this\\is\\a\\test\\path\\with\\a\\file\\at\\the\\end\\file.txt"
    //         )?,
    //         "file.txt",
    //         "strip path failed to strip the end of a win path, with a file at the end"
    //     );
    //     assert_eq!(
    //         super::strip_path("/this/is/a/test/path/with/a/file/at/the/end/file.txt")?,
    //         "file.txt",
    //         "strip path failed to strip the end of a rust path, with a file at the end"
    //     );
    //     Ok(())
    // }

    #[test]
    fn set_dll() {
        let mut inj = super::Injector::default();
        let dll = crate::Data::Str(STR);
        inj.set_dll(dll);
        assert_eq!(inj.dll, dll, "Setter did not correctly set the dll string");
    }
    #[test]
    fn set_pid() {
        let mut inj = super::Injector::default();
        const PID: u32 = 0;
        inj.set_pid(PID);
        assert_eq!(inj.pid, PID, "Setter did not correctly set the PID");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn cmp() {
        simple_logger::SimpleLogger::new().init().ok();
        //Simple case
        {
            let f = super::cmp(crate::Data::Str("test"));
            assert!(f(crate::Data::Str("test")));
            assert!(f(crate::Data::Str("something test")));
            assert!(!f(crate::Data::Str("something 1351")));
            let f = super::cmp(crate::Data::Str("KERNEL32.DLL"));
            assert!(f(crate::Data::Str("C:\\Windows\\System32\\KERNEL32.DLL")));
            let f = super::cmp(crate::Data::Str("ntdll.dll"));
            assert!(f(crate::Data::Str("C:\\Windows\\SYSTEM32\\ntdll.dll")));
        }
        //complicated paths
        #[cfg(feature = "std")]
        {
            let f = std::vec![
                super::cmp(crate::Data::Path(std::path::Path::new(
                    r"C:\this\is\a\test\path\with\a\dir\at\the\end\"
                ))),
                super::cmp(crate::Data::Path(std::path::Path::new(
                    r"C:\this\is\a\test\path\with\a\dir\at\the\end"
                ))),
                super::cmp(crate::Data::Path(std::path::Path::new(
                    "C:/this/is/a/test/path/with/a/dir/at/the/end/"
                ))),
                super::cmp(crate::Data::Path(std::path::Path::new(
                    "C:/this/is/a/test/path/with/a/dir/at/the/end"
                ))),
            ];
            for f in f {
                assert!(f(crate::Data::Str("end")));
                assert!(f(crate::Data::Str("the\\end")));
                assert!(f(crate::Data::Str("the/end")));
                assert!(f(crate::Data::Str("at/the\\end")));
                assert!(f(crate::Data::Str("at\\the/end")));
                assert!(f(crate::Data::Path(std::path::Path::new("end"))));
                assert!(f(crate::Data::Path(std::path::Path::new("the\\end"))));
                assert!(f(crate::Data::Path(std::path::Path::new("the/end"))));
                assert!(f(crate::Data::Path(std::path::Path::new("at/the\\end"))));
                assert!(f(crate::Data::Path(std::path::Path::new("at\\the/end"))));
            }
        }
        {
            let f = super::cmp(crate::Data::Str(
                r"C:\this\is\a\test\path\with\a\dir\at\the\end\",
            ));
            assert!(!f(crate::Data::Str("end")));
            assert!(!f(crate::Data::Str(r"the\end")));
            assert!(f(crate::Data::Str(r"end\")));
            let f = super::cmp(crate::Data::Str(
                r"C:\this\is\a\test\path\with\a\dir\at\the\end",
            ));
            assert!(f(crate::Data::Str("end")));
            assert!(f(crate::Data::Str(r"the\end")));
            assert!(!f(crate::Data::Str(r"end\")));
            assert!(!f(crate::Data::Str(r"the\end\")));
            let f = super::cmp(crate::Data::Str(
                "C:/this/is/a/test/path/with/a/dir/at/the/end/",
            ));
            assert!(f(crate::Data::Str("end/")));
            assert!(f(crate::Data::Str("the/end/")));
            assert!(!f(crate::Data::Str("end")));
            assert!(!f(crate::Data::Str("the/end")));
            let f = super::cmp(crate::Data::Str(
                "C:/this/is/a/test/path/with/a/dir/at/the/end",
            ));
            assert!(f(crate::Data::Str("end")));
            assert!(!f(crate::Data::Str("end/")));
            assert!(!f(crate::Data::Str("the/end/")));
        }
    }
}
