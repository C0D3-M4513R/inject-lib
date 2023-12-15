#![cfg(target_family = "windows")]
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "alloc"))]
compile_error!("Cannot work without alloc");
#[cfg(not(feature = "std"))]
compile_error!("Currently no-std is not supported, because I cannot find a stable way to make rust happy with the panic handler and eh_personality");

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::null_mut;
use inject_lib::{Data, Inject, Injector};

///Reads len bytes from ptr, and returns it as a vec
fn read(ptr: *mut u8, len: usize) -> Vec<u8> {
    #[cfg(feature = "std")]
    println!("reading {} bytes from {:x?}", len, ptr);
    let mut v = Vec::with_capacity(len);
    for i in 0..len {
        v.push(unsafe { *ptr.add(i) });
    }
    v
}

#[no_mangle]
///Takes a utf8 string pointer, along with the size, the pointer is valid
///A return code of 0 means success.
pub extern "C" fn inject(pid: u32, dll: *mut u8, len: usize, wait: bool) -> i16 {
    let v = read(dll, len);
    let dll = String::from_utf8(v);
    if dll.is_err() {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
        return -2;
    }
    let dll = unsafe { dll.unwrap_unchecked() }; //Safety: checked and handled above;
    let i = Injector::new(Data::Str(dll.as_str()), pid);
    let r = i.inject(wait).inject();
    if let Err(e) = r {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR: {}", e);
        return -1;
    }
    return 0;
}

#[no_mangle]
///Takes a utf8 string pointer, along with the size, the pointer is valid
///A return code of 0 means success.
pub extern "C" fn eject(pid: u32, dll: *mut u8, len: usize, wait: bool) -> i16 {
    let v = read(dll, len);
    let dll = String::from_utf8(v);
    if dll.is_err() {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
        return -2;
    }
    let dll = unsafe { dll.unwrap_unchecked() }; //Safety: checked and handled above;
    let i = Injector::new(Data::Str(dll.as_str()), pid);
    let r = i.inject(wait).eject();
    if let Err(e) = r {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR: {}", e);
        return -1;
    }
    return 0;
}

#[repr(C)]
pub struct FindPid {
    pub len: usize,
    pub arr: *mut u32,
    pub exitcode: i16,
}

#[no_mangle]
///Takes a utf8 string pointer, along with the size, the pointer is valid
///Returns a array of pids, if exitcode=0.
pub extern "C" fn find_pid(name: *mut u8, len: usize) -> FindPid {
    let v = read(name, len);
    let name = String::from_utf8(v);
    if name.is_err() {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR: Non UTF-8 String found.");
        return FindPid {
            len: 0,
            arr: null_mut(),
            exitcode: -2,
        };
    }
    let name = unsafe { name.unwrap_unchecked() }; //Safety: checked and handled above;
    let vec = Injector::find_pid(Data::Str(name.as_str()));
    return if let Ok(vec) = vec {
        let v = vec.leak();
        #[cfg(feature = "std")]
        eprintln!("{:x?}", v.as_mut_ptr());
        FindPid {
            len: v.len(),
            arr: v.as_mut_ptr(),
            exitcode: 0,
        }
    } else {
        #[cfg(feature = "std")]
        eprintln!("inject-lib: ERROR:  {}", vec.unwrap_err());
        FindPid {
            len: 0,
            arr: null_mut(),
            exitcode: -1,
        }
    }
}
