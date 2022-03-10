# dll_injector
This library(will later be a crate) exists, to inject a dll into a windows process.
This injector currently supports, injecting from x64 into x86 and x64, and injecting from x86 into x86.

Inejecting from x86 into x64 is theoretically possible. I am just too dumb, to call a function in assembly.
# Todos:

- Find a good name
- Make the injector work also on x86->x64
- Get reliable exit codes.