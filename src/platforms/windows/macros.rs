#![cfg(target_os = "windows")]

use std::fmt::Display;
use crate::platforms::platform::Result;
use log::{debug, error, info, trace, warn};
use winapi::um::errhandlingapi::GetLastError;

// use crate::platforms::platform::check_nt_status;
// use winapi::um::handleapi::CloseHandle;

///NOP function.
///This exists, to do the same as #[allow(unused_must_use)].
///The above doesn't work for me right now though.
#[inline]
pub fn void_res<T>(_: Result<T>) {}

macro_rules! check_ptr {
    ($name:ident($($args:expr),*),$predicate:expr)=>{
        {
            let _tmp = unsafe{$name($($args),*)};
            if $crate::macros::__call__(_tmp,$predicate){
                return $crate::platforms::platform::macros::err(std::stringify!($name));
            } else{
               _tmp
            }
        }
    };
    ($name:ident($($args:expr),*))=>{
        $crate::platforms::platform::macros::check_ptr!($name($($args),*),|v|v.is_null())
    };
}
pub(crate) use check_ptr;

///Gets the windows Error, prints it, and returns an error.
pub(crate) fn err<T, E>(fn_name: E) -> Result<T>
where
    E: Display,
{
    let err = unsafe { GetLastError() };
    error!("{} failed! Errcode is:'{}'. Check, what the error code means here:'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes'", fn_name, err);
    Err((fn_name.to_string(), err))
}

///Checks a NtStatus, using [check_nt_status].
///If [check_nt_status] returns Some value, it returns it, as an Err.
macro_rules! check_nt_status {
	($status:expr)=>{
		{
			let status = $status;
			if let Some(tmp)=check_nt_status(status){
				return Err(tmp);
			}
			status
		}
	}
}
pub(crate) use check_nt_status;
