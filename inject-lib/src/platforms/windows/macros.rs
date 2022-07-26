#![cfg(target_os = "windows")]

use crate::error::Error;
use winapi::um::errhandlingapi::GetLastError;

///Calls a closure
#[doc(hidden)]
pub(crate) fn __call__<T, R>(arg: T, f: impl FnOnce(T) -> R) -> R {
    f(arg)
}

macro_rules! check_ptr {
    ($name:ident($($args:expr),*),$predicate:expr)=>{
        {
            #[allow(unsafe_op_in_unsafe_fn)]//We might call this in a unsafe function
            #[allow(unused_unsafe)]
            let _tmp = unsafe{$name($($args),*)};
            if $crate::platforms::windows::macros::__call__(_tmp,$predicate){
                return Err($crate::error::Error::from(core::stringify!($name)));
            } else{
               _tmp
            }
        }
    };
    ($name:ident($($args:expr),*))=>{
        $crate::platforms::windows::macros::check_ptr!($name($($args),*),|v|v.is_null())
    };
}
pub(crate) use check_ptr;

///Gets the windows Error, prints it, and returns an error.
pub(crate) fn err(fn_name: &'static str) -> Error {
    let err = unsafe { GetLastError() };
    crate::error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
    Error::Winapi(fn_name, err)
}
