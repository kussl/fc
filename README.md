# Fidelius charm
Fidelius charm (FC) is a project for securing interactions with C code within a Rust program. The idea of this project is to use system-level support for protecting memory regions with sensitive data when executing code in an extern C function. FC includes functions and macros to facilitate protecting memory before entering an `unsafe` block. FC uses `mprotect` to change permission on sensitive memory pages. FC also includes a kernel module that would assist the library with protecting calls to the `mprotect` system call.

This project is still under development and should not be included into production code. 

This is an example code on using FC to isolate a memory page before an FFI call in Rust: 

```
use fc::core::*;

fn uses_ffi_at_some_point() { 
  /* Create a padding to isolate the return address. */
  stack_padding!();
  let secret1 = "secret"; 
  let mut secret2 = vec![1, 2, 3];
  
  /*
  1. Introduce padding to isolate the memory page for the bindings above.
  2. Protect the isolated memory page.
  3. Disable access to mprotect.
  */
  stack_padding!(); 
  
  //Key used as argument to find the start address of the page.
  immutable_sc(&secret1);
  //This one is for the heap memory allocated for secret2.
  immutable_sc((&secret2[0]));
  //Communicate the secret key to the kernel. 
  kernel_disable!(&memory_page_addr_usize!(secret1));
  
  let p = 10; 
  
  let r = unsafe { 
      some_very_vulnerable_function(&p); 
  };
  
  /*
  Reverse everything by
  1. Enabling access to mprotect again.
  2. Changing all page permissions back to normal.
  */
  kernel_enable!();
  normal_sc(&secret1);
  normal_sc(&secret2[0]); 
}
```
            
