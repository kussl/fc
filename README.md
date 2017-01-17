# Fidelius charm
Fidelius charm (FC) is a project for securing interactions with C code within a Rust program. The idea of this project is to use system-level support for protecting memory regions with sensitive data when executing code in an extern C function. FC includes functions and macros to facilitate protecting memory before entering an `unsafe` block. FC uses `mprotect` to change permission on sensitive memory pages. FC also includes a kernel module that would assist the library with protecting calls to the `mprotect` system call.

This project is still under development and should not be included into production code. 
