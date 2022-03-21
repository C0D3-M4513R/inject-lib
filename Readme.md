# dll_injector
This library(will later be a crate) exists, to inject a dll into a windows process.
This injector currently supports injecting from x64 into x86 and x64, and injecting from x86 into x86 (and x64 [if compiled with correct features]).

## Todos

- [ ] Find a good name
- [x] Make the injector work also on x86->x64
- [x] Get reliable exit codes/Redo error system.
- [ ] Rework the outfacing api, to allow more control.
- [ ] Use std::os::windows::process::OwnedHandle when stable
