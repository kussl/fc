# Fidelius charm
Fidelius charm (FC) is a project for securing interactions with C code within a Rust program. The idea of this project is to use system-level support for protecting memory regions with sensitive data when executing code in an extern C function. FC includes functions and macros to facilitate protecting memory before entering an `unsafe` block. FC uses `mprotect` to change permission on sensitive memory pages. FC also includes a kernel module that would assist the library with protecting calls to the `mprotect` system call.

This project is still under development and should not be included into production code. 

This is an example code on using FC to isolate a memory page before an FFI call in Rust: 

```
use fc::core::*;

fn uses_ffi_at_some_point() { 
  /* Create a padding to isolate the return address. */
  create_padding!();
  let secret1 = "secret"; 
  let mut secret2 = vec![1, 2, 3];
  
  /*
  1. Generate a key
  2. Introduce padding to isolate the memory page for the bindings above.
  3. Protect the isolated memory page.
  4. Disable access to mprotect.
  */
  let kernel_key = get_kernel_key!();
  create_padding!(); 
  
  //Key used as argument to find the start address of the page.
  immutable_single_stack_page(&secret1);
  //This one is for the heap memory allocated for secret2.
  immutable_single_stack_page((&secret2[0]));
  //Communicate the secret key to the kernel. 
  disable_mprotect_stack(&kernel_key, &memory_page_addr_usize!(key));
  
  let p = 10; 
  
  let r = unsafe { 
      some_very_vulnerable_function(&p); 
  };
  
  /*
  Reverse everything by
  1. Enabling access to mprotect again.
  2. Changing all page permissions back to normal.
  */
  enable_mprotect_stack(&kernel_key);
  mutable_single_stack_page(&secret1);
  mutable_single_stack_page((&secret2[0])); 
}
```
            
