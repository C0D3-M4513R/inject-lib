use crate::Result;
use log::trace;
use std::ops::Deref;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;

#[repr(transparent)]
pub struct Thread {
    thread: HANDLE,
}

impl Thread {
    pub unsafe fn new(thread: HANDLE) -> Result<Thread> {
        if thread.is_null() {
            return Err(("Not a valid HANDLE".to_string(), 0));
        }
        Ok(Thread { thread })
    }
}
impl Deref for Thread {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.thread
    }
}
impl Drop for Thread {
    fn drop(&mut self) {
        trace!("Cleaning Thread Handle");
        if unsafe { winapi::um::handleapi::CloseHandle(self.thread) } == FALSE {
            log::error!("Error during cleanup!");
            //Supress unused_must_use warning. This is intended, but one cannot use allow, to supress this?
            //todo: a bit hacky? Is there a better way, to achieve something similar?
            crate::platforms::platform::macros::void_res(
                crate::platforms::platform::macros::err::<(), String>(
                    "CloseHandle of Thread".to_string(),
                ),
            );
            //Panic's during drop could lead to abort.
            // panic!("Error during cleanup");
        }
    }
}
