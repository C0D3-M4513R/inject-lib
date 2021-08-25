# dll_injector
This library(will later be a crate) exists, to inject a dll into a windows process.
This injector currently supports, injecting from x64 into x86 and x64, and injecting from x86 into x86.

Inejecting from x86 into x64 is not supported, since I currently use `CreateToolhelp32Snapshot`.
More infos [here](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).

# Todos:

- Find a good name
- Make the injector work also on x86->x64
- Get reliable exit codes.