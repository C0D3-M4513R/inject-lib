#[cfg(target_os = "windows")]
#[path = "platforms/windows/mod.rs"]
mod platform;

#[cfg(all(target_arch = "x86", feature = "x86tox64"))]
mod x86;
