#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(all(target_arch = "x86", feature = "x86tox64"))]
mod x86;
