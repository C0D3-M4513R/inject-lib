#![cfg(target_os = "windows")]

use crate::error::Error;
use log::{debug, error, info, trace, warn};
use std::fmt::Display;
use winapi::um::errhandlingapi::GetLastError;

///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
pub fn void_res<T>(_: T) {}

///Calls a closure
pub(crate) fn __call__<T, R>(arg: T, f: impl FnOnce(T) -> R) -> R {
    f(arg)
}

macro_rules! check_ptr {
    ($name:ident($($args:expr),*),$predicate:expr)=>{
        {
            let _tmp = unsafe{$name($($args),*)};
            if $crate::platforms::windows::macros::__call__(_tmp,$predicate){
                return Err($crate::error::Error::from(std::stringify!($name)));
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
pub(crate) fn err<E>(fn_name: E) -> Error
where
    E: Display,
{
    let err = unsafe { GetLastError() };
    error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
    Error::Winapi(fn_name.to_string(), err)
}
