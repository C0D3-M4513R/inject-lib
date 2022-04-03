use std::ffi::OsString;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Winapi(String, u32),
    Ntdll(i32),
    WTFConvert(OsString), //Windows u16 string stuff
    Io(std::io::Error),
    #[cfg(target_family = "windows")]
    Pelite(pelite::Error),
    Unsupported(Option<String>),
    Unsuccessful(Option<String>),
}

impl From<std::io::Error> for Error {
    ///Converts a std::Io::Error into a Error for use in this crate
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
impl Error {
    ///Gets the contents of Error::Winapi, if self holds data of that type
    fn get_winapi(&self) -> Option<(&String, &u32)> {
        match self {
            Error::Winapi(x, y) => Some((x, y)),
            _ => None,
        }
    }
    ///Gets the contents of Error::NTDLL, if self holds data of that type
    fn get_ntdll(&self) -> Option<&i32> {
        match self {
            Error::Ntdll(x) => Some(x),
            _ => None,
        }
    }
    ///Gets the contents of Error::WTFConvert, if self holds data of that type
    fn get_wtfconvert(&self) -> Option<&OsString> {
        match self {
            Error::WTFConvert(x) => Some(x),
            _ => None,
        }
    }
    ///Gets the contents of Error::Io, if self holds data of that type
    fn get_io(&self) -> Option<&std::io::Error> {
        match self {
            Error::Io(x) => Some(x),
            _ => None,
        }
    }
    ///Gets the contents of Error::Unsupported, if self holds data of that type
    fn get_unsupported(&self) -> Option<&Option<String>> {
        match self {
            Error::Unsupported(x) => Some(x),
            _ => None,
        }
    }
    ///Gets the contents of Error::Unsuccessful, if self holds data of that type
    fn get_unsuccessful(&self) -> Option<&Option<String>> {
        match self {
            Error::Unsuccessful(x) => Some(x),
            _ => None,
        }
    }
    #[cfg(target_family = "windows")]
    ///Gets the contents of Error::NTDLL, if self holds data of that type
    fn get_pelite(&self) -> Option<&pelite::Error> {
        match self {
            Error::Pelite(x) => Some(x),
            _ => None,
        }
    }
}
//due to equality testing for Error::Io, we cannot impl Eq for Error{}
impl PartialEq<Self> for Error {
    fn eq(&self, other: &Self) -> bool {
        fn helper(me: &Error, other: &Error) -> Option<bool> {
            Some(match me {
                Error::Winapi(x, y) => other.get_winapi()?.eq(&(x, y)),
                Error::Ntdll(x) => other.get_ntdll()?.eq(x),
                Error::WTFConvert(x) => other.get_wtfconvert()?.eq(x),
                Error::Io(x) => other.get_io()?.kind() == x.kind(), //todo:improve equality testing for Error::Io
                #[cfg(target_family = "windows")]
                Error::Pelite(x) => other.get_pelite()?.eq(x),
                Error::Unsupported(x) => other.get_unsupported()?.eq(x),
                Error::Unsuccessful(x) => other.get_unsuccessful()?.eq(x),
            })
        }
        *helper(self, other).get_or_insert(false)
    }
}

#[cfg(target_family = "windows")]
mod windows {
    use crate::error::Error;
    use winapi::um::errhandlingapi::GetLastError;

    impl From<pelite::Error> for Error {
        fn from(e: pelite::Error) -> Self {
            Error::Pelite(e)
        }
    }
    impl From<String> for Error {
        fn from(s: String) -> Self {
            Error::Winapi(s, unsafe { GetLastError() })
        }
    }
    impl<'a> From<&'a str> for Error {
        fn from(s: &'a str) -> Self {
            Error::Winapi(s.to_string(), unsafe { GetLastError() })
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Winapi(s, n) => write!(f, "Winapi error:{} failed with code {}", s, n),
            Error::Ntdll(n) => write!(f, "Ntdll Error:{:#x}", n),
            Error::WTFConvert(_) => write!(f, "Error: Buffer contained non UTF-8 characters."), //todo: should I print osstring here?
            Error::Unsupported(r) => write!(
                f,
                "Unsupported({})",
                if let Some(s) = r { s } else { "None" }
            ),
            Error::Unsuccessful(r) => write!(
                f,
                "Unsuccessful({})",
                if let Some(s) = r { s } else { "None" }
            ),
            Error::Io(e) => write!(f, "{}", e),
            #[cfg(target_family = "windows")]
            Error::Pelite(e) => write!(f, "{}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Ntdll {
    Success(i32),
    Information(i32),
    Warning(i32),
    Error(i32),
    Other(i32),
}

impl Ntdll {
    pub fn get_status(&self) -> &i32 {
        match self {
            Ntdll::Error(v) => v,
            Ntdll::Warning(v) => v,
            Ntdll::Other(v) => v,
            Ntdll::Success(v) => v,
            Ntdll::Information(v) => v,
        }
    }
}
impl Display for Ntdll {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Ntdll::Error(v) => write!(f, "Ntdll::Error({:#x})", v),
            Ntdll::Warning(v) => write!(f, "Ntdll::Warning({:#x})", v),
            Ntdll::Other(v) => write!(f, "Ntdll::Other({:#x})", v),
            Ntdll::Success(v) => write!(f, "Ntdll::Success({:#x})", v),
            Ntdll::Information(v) => write!(f, "Ntdll::Information({:#x})", v),
        }
    }
}

#[cfg(windows)]
pub mod ntdll {
    use crate::error::{Error, Ntdll};
    use log::error;
    use winapi::shared::ntdef::{NTSTATUS, NT_ERROR, NT_INFORMATION, NT_SUCCESS, NT_WARNING};

    impl crate::error::Ntdll {
        ///Create a new Ntdll enum from a NTSTATUS
        pub fn new(n: NTSTATUS) -> Self {
            if NT_ERROR(n) {
                Ntdll::Error(n)
            } else if NT_WARNING(n) {
                Ntdll::Warning(n)
            } else if NT_INFORMATION(n) {
                Ntdll::Information(n)
            } else if NT_SUCCESS(n) {
                Ntdll::Success(n)
            } else {
                error!("");
                Ntdll::Other(n)
            }
        }
        ///Returns true, if the enum contains Error discriminant
        pub fn is_error(&self) -> bool {
            match self {
                Ntdll::Error(_) => true,
                _ => false,
            }
        }
        ///Returns true, if the enum contains Warning discriminant
        pub fn is_warning(&self) -> bool {
            match self {
                Ntdll::Warning(_) => true,
                _ => false,
            }
        }
        ///Returns true, if the enum contains Information discriminant
        pub fn is_info(&self) -> bool {
            match self {
                Ntdll::Information(_) => true,
                _ => false,
            }
        }
        ///Returns true, if the enum contains Success discriminant
        pub fn is_success(&self) -> bool {
            match self {
                Ntdll::Success(_) => true,
                _ => false,
            }
        }
        ///Returns true, if the enum contains Other discriminant
        pub fn is_other(&self) -> bool {
            match self {
                Ntdll::Other(_) => true,
                _ => false,
            }
        }
    }
    impl Into<Error> for Ntdll {
        ///Transform Ntdll enum into Error
        fn into(self) -> Error {
            match self {
                Ntdll::Error(v) => Error::Ntdll(v),
                Ntdll::Warning(v) => Error::Ntdll(v),
                Ntdll::Information(v) => Error::Ntdll(v),
                Ntdll::Success(v) => Error::Ntdll(v),
                Ntdll::Other(v) => Error::Ntdll(v),
            }
        }
    }
}
