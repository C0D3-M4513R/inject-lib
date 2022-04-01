use crate::error::Error;
use crate::platforms::platform::macros::err;
use crate::Result;
use log::{info, trace};
use std::ops::Deref;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;

#[repr(transparent)]
pub struct Thread {
    thread: HANDLE,
}

impl Thread {
    ///# Safety
    ///User must ensure, that thread is a valid Thread handle.
    pub(crate) unsafe fn new(thread: HANDLE) -> Result<Thread> {
        if thread.is_null() {
            return Err(err("CreateThread"));
        }

        Ok(Thread { thread })
    }
    ///This Function waits for a thread to exit.
    ///This Function assumes, that this object has a valid thread handle already.
    pub(crate) fn wait_for_thread(&self) -> Result<()> {
        info!("Waiting for thread");
        return match unsafe { WaitForSingleObject(self.thread, INFINITE) } {
            0x80 => Err(Error::Winapi(
                "WaitForSingleObject returned WAIT_ABANDONED".to_string(),
                0x80,
            )), //WAIT_ABANDONED
            0x0 => {
                info!("Dll eject success? IDK?! Hopefully? WaitForSingleObject returned WAIT_OBJECT_0");
                Ok(())
            } //WAIT_OBJECT_0
            0x102 => Err(Error::Winapi(
                "Timeout hit at WaitForSingleObject.".to_string(),
                0x102,
            )), //WAIT_TIMEOUT
            0xFFFFFFFF => Err(Error::Winapi(
                "Wait_Failed hit at WaitForSingleObject.".to_string(),
                0xFFFFFFFF,
            )), //WAIT_FAILED
            e => Err(Error::Unsuccessful(Some(format!(
                "WaitForSingleObject return code {}",
                e
            )))),
        };
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
                crate::platforms::platform::macros::err::<String>(
                    "CloseHandle of Thread".to_string(),
                ),
            );
            //Panic's during drop could lead to abort.
            // panic!("Error during cleanup");
        }
    }
}
