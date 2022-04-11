#![cfg(target_family = "windows")]
extern crate inject_lib;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::ptr::null_mut;
use inject_lib::Injector;
use inject_lib::error::Error;

#[repr(C)]
pub enum Result<T>{
	Ok(T),
	Err(CString)
}

#[no_mangle]
pub extern "C" fn inject(pid:u32,dll:*mut c_char)->i16{
	let dll=unsafe{CStr::from_ptr(dll).to_str()};
	if dll.is_err(){
		eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
		return -2;
	}
	let dll=unsafe{dll.unwrap_unchecked()};//Safety: checked and handled above;
	let i = Injector::new(dll,pid);
	let r =i.inject();
	if let Err(e)=r{
		eprintln!("inject-lib: ERROR: {}",e);
		return -1;
	}
	return 0;
}

#[no_mangle]
pub extern "C" fn eject(pid:u32,dll:*mut c_char)->i16{
	let dll=unsafe{CStr::from_ptr(dll).to_str()};
	if dll.is_err(){
		eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
		return -2;
	}
	let dll=unsafe{dll.unwrap_unchecked()};//Safety: checked and handled above;
	let i = Injector::new(dll,pid);
	let r =i.eject();
	if let Err(e)=r{
		eprintln!("inject-lib: ERROR: {}",e);
		return -1;
	}
	return 0;
}


#[repr(C)]
pub struct FindPid {
	pub len:usize,
	pub arr:*mut u32,
	pub exitcode:i16
}

#[no_mangle]
pub extern "C" fn find_pid(name:*mut c_char)-> FindPid {
	let name =unsafe{CStr::from_ptr(name).to_str()};
	if name.is_err(){
		eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
		return FindPid{
			len:0,
			arr:null_mut(),
			exitcode:-2,
		};
	}
	let dll=unsafe{ name.unwrap_unchecked()};//Safety: checked and handled above;
	let vec=Injector::find_pid(name.unwrap());
	if let Ok(vec)=vec{
		return FindPid{
			len:vec.len(),
			arr:vec.leak().as_mut_ptr(),
			exitcode:0
		}
	}else{
		eprintln!("inject-lib: ERROR:  {}",vec.unwrap_err());
		return FindPid{
			len:0,
			arr:null_mut(),
			exitcode:-1,
		};
	}
}
