use crate::Result;
use ntapi::ntapi_base::{CLIENT_ID64, PCLIENT_ID64};
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::{NTSTATUS, PVOID, ULONG};
use winapi::um::winnt::{BOOLEAN, HANDLE, PSECURITY_DESCRIPTOR};

///This struct holds the necessary data for a RTLCreateThread call all in once place, so it can be accessed easily, by pointer manipulation.
#[repr(C)]
#[allow(non_snake_case)]
pub(crate) struct RtlCreateThreadParam {
    pub ProcessHandle: u64,      //ptr
    pub SecurityDescriptor: u64, //ptr
    pub CreateSuspended: u64,
    pub StackZeroBits: u64,
    pub MaximumStackSize: u64,
    pub StackCommit: u64,
    pub StartAddress: u64,   //ptr
    pub StartParameter: u64, //ptr
    pub ThreadHandle: u64,   //ptr
    pub ClientID: u64,       //ptr
}

///This Calls va in a x64 context, with the call-specification of RtlCreateThreadParam.
unsafe fn asm(va: u64, params: *mut RtlCreateThreadParam) -> NTSTATUS {
    let mut esp = (0usize, 0usize);
    //Save Previous esp. (Not that it will do any good, if it isn't aligned afterwards.
    core::arch::asm!("mov {},esp",lateout(reg) esp.0 ,options(nomem,preserves_flags,nostack));
    //https://github.com/rwfpl/rewolf-wow64ext/blob/fd28b57fe926f3e57540850c37cdbcc766173dba/src/internal.h#L26
    //https://github.com/rwfpl/rewolf-wow64ext/blob/master/src/internal.h
    crate::debug!("Start of scary asm block.");
    let mut r: NTSTATUS;
    core::arch::asm!(
        "push 0x33",
        "call 2f",
        "2:",
        "add dword ptr [esp],5",
        "retf",
        ".code64",
        //Transision to x64
        "mov rax,rsp",
        "and rsp, 0xFFFFFFFFFFFFFFF0",
        "push rax",
        //This aligned the esp to 16 bit boundary
        "sub     rsp, 88", //Alloc mem
        "mov     r11, [rcx]",
        "mov     r9d, DWORD PTR [rdx+24]",
        "movzx   r8d, BYTE PTR [rdx+16]",
        "mov     rax, QWORD PTR [rdx+72]",
        "mov     QWORD PTR [rsp+72], rax",
        "mov     rax, QWORD PTR [rdx+64]",
        "mov     rcx, QWORD PTR [rdx]",
        "mov     QWORD PTR [rsp+64], rax",
        "mov     rax, QWORD PTR [rdx+56]",
        "mov     QWORD PTR [rsp+56], rax",
        "mov     rax, QWORD PTR [rdx+48]",
        "mov     QWORD PTR [rsp+48], rax",
        "mov     rax, QWORD PTR [rdx+40]",
        "mov     QWORD PTR [rsp+40], rax",
        "mov     rax, QWORD PTR [rdx+32]",
        "mov     rdx, QWORD PTR [rdx+8]",
        "mov     QWORD PTR [rsp+32], rax",
        "call    r11",
        "add     rsp, 88",
        //Do some shit and call the function. Thanks compiler.
        //Hope and pray. Call to the specified function. Here RTLCreateUserThread
        "pop rsp",
        //Restore old esp value, before we aligned it.
        "call 3f",
        "3:",
        "mov dword ptr [rsp + 4],0x23",
        "add dword ptr [rsp],0xD",
        "retf",
        ".code32",
        //Transitions back to x86
        "mov ax,ds",
        "mov ss,ax",
        "push edx",
        "pop edx",
        //Thanks to http://blog.rewolf.pl/blog/?p=1484 and fuck you AMD.
        in("ecx") &va as *const u64,
        in("edx") params,
        out("eax") r,
        clobber_abi("system")
    );
    core::arch::asm!("mov {0},esp",lateout(reg) esp.1,options(nomem,preserves_flags,nostack));
    assert_eq!(
        esp.0, esp.1,
        "esp was changed, from injecting.\
		I cannot guarantee ANYTHING now.\
		Rust expects esp to not change.\
		There is no possible way to recover (and there likely will never be).\
		IF you encounter this in production, open an issue. This is a CRITICAL bug."
    );
    crate::debug!("esp is {:x}, was {:x}, return is {:x}", esp.1, esp.0, r);
    r
}
///This function will call a function specified by va, with the same Call arguments, that you would call RTLCreateRemoteThread.
///This function is only intended to work with RTLCreateRemoteThread
pub(crate) unsafe fn exec(
    va: u64,
    process_handle: HANDLE,
    security_descriptor: PSECURITY_DESCRIPTOR,
    create_suspended: BOOLEAN,
    zero_bits: ULONG,
    maximum_stack_size: SIZE_T,
    committed_stack_size: SIZE_T,
    start_addres: u64,
    parameter: u64,
) -> Result<(NTSTATUS, HANDLE, CLIENT_ID64)> {
    let mut thread: u64 = 0;
    let mut client: ntapi::ntapi_base::CLIENT_ID64 = CLIENT_ID64 {
        UniqueProcess: 0,
        UniqueThread: 0,
    };
    crate::trace!(
        "{:x}({:x},{:x},{:x},{:x},{:x},{:x},{:x},{:x},{:x},{:x})",
        va,
        process_handle as usize,
        core::ptr::null_mut() as PVOID as usize,
        0,
        0,
        0,
        0,
        start_addres as u64,
        parameter as u64,
        &mut thread as *mut u64 as usize,
        &mut client as PCLIENT_ID64 as usize
    );
    let mut pass_asm = RtlCreateThreadParam {
        ProcessHandle: process_handle as u64,
        SecurityDescriptor: security_descriptor as u64,
        CreateSuspended: create_suspended as u64,
        StackZeroBits: zero_bits as u64,
        MaximumStackSize: maximum_stack_size as u64,
        StackCommit: committed_stack_size as u64,
        StartAddress: start_addres as u64,
        StartParameter: parameter as u64,
        ThreadHandle: &mut thread as *mut u64 as u64,
        ClientID: &mut client as PCLIENT_ID64 as u64,
    };
    let r = asm(va, &mut pass_asm as *mut RtlCreateThreadParam);
    Ok((r, thread as HANDLE, client))
}

#[cfg(test)]
mod test {
    use crate::Result;
    use std::ptr::null_mut;

    //defines a noop function
    core::arch::global_asm!(".code64", "nopx64:", "enter 0,0", "leave", "ret");

    #[test]
    fn exec() -> Result<()> {
        //I am only testing, if the asm function causes any behavior that would cause the program to exit unexpectedly
        unsafe {
            let a: usize;
            core::arch::asm!("lea {},nopx64",out(reg) a,options(preserves_flags,nomem,nostack));
            super::exec(a as u64, null_mut(), null_mut(), 0, 0, 0, 0, 0, 0)?;
        }
        Ok(())
    }
}
