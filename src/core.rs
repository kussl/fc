use libc::mprotect;
use libc::PROT_READ;
use libc::PROT_WRITE;
use libc::PROT_EXEC;
use libc::PROT_NONE;
use libc::c_void;
use rand::random;
// use std::fmt;


/*
A general function to disable or enable mprotect, or to add
additional page addresses after disabling mprotect. Each of the three
operations have a unique code that will be chosen based on the caller's request parameter.
request = 0 (disable) | 1 (enable) | 2 (addpages)
*/
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn kernel_protocol(request: i8, page: usize) {
    let mut code = 0x00A00A00C;
    if request == 1 {
        code = 0x00A00A00D;
    }
    else if request == 2 {
        code = 0x00A00A00B;
    }
    //println!("Code: 0x{:X}", code);
    /*
    rax: system call number
    rbx: 0 (i.e., ignore)
    rcx: 0 (i.e., ignore)
    rdx: request from the kernel
    */
    unsafe {
        asm!("movq $$0x7D, %rax
              movq $$0, %rbx
              movq $0, %rcx
              movq $1, %rdx
              int $$0x80
              " //jmp *$0
              : /* no outputs */
              : "m"(page),"m"(code)
              : "rax", "rbx", "rcx", "rdx");
    }
    let _ = 100;
}

/*
Two macros to facilitate use of kernel_protocol
*/

#[macro_export]
macro_rules! kernel_disable {
    ($x:expr) => (kernel_protocol(0,$x););
}
#[macro_export]
macro_rules! kernel_enable {
    () => (kernel_protocol(1,0););
}

/*
Memory page address calculator based on page size
*/

#[macro_export]
macro_rules! page_size {
    () => (4096);
}

#[macro_export]
macro_rules! memory_page_addr {
    ($x:expr) => (((&$x as *const _) as i64) & !(4095));
}

#[macro_export]
macro_rules! page_addr {
    ($x:expr) => ( $x & !(4095) );
}

/*
Only used for debugging purposes.
*/
#[macro_export]
macro_rules! print_memory_addr {
    ($x:expr, $y:expr) => (println!("{:} address: {:?} at page 0x{:X}", $y, &$x as *const _, ((&$x as *const _) as i64) & !(4095)));
}

/*
Padding
*/
const P_DEFAULT: usize = 512;

pub struct Padding {
    pub space: [i64; P_DEFAULT]
}

impl Default for Padding {
    fn default() -> Padding { Padding {space: [random::<i64>(); P_DEFAULT]} }
}

#[macro_export]
macro_rules! stack_padding {
    () => (let _: Padding = Padding::default(););
}




/*
Secure compartments
*/

/*
This function receives a pointer to one of the bindings
on a stack page. It will compute the start address of the page and will attempt to set the page to read only. The challenge is to avoid possible crashes because of wrong page numbering or because the page may be used in the future. For now, it will assume the page can safely be protected. Avoid calling other functions or introducing new bindings as much as possible, except for mprotect and the padding requirement, of course.
*/

fn modify_page_permissions(addr: i64, permission: i32) {
    unsafe {
        mprotect( (addr & !(4095)) as *mut c_void, 4096, permission );
    }
}

pub fn immutable_sc<T>(x: &T) {
    modify_page_permissions(((x as *const _) as i64), PROT_READ);
}

pub fn immutable_sc_u(x: i64) {
    //stack_padding!();
    modify_page_permissions(x, PROT_READ);
}

/*
Same as immutable_sc but sets the page permission to NONE. No one can use the page.
*/
pub fn private_sc<T>(x: &T) {
    modify_page_permissions(((x as *const _) as i64), PROT_NONE);
}

pub fn normal_sc<T>(x: &T) {
    modify_page_permissions(((x as *const _) as i64), PROT_READ | PROT_WRITE);
}


pub fn private_sc_u(x: i64) {
    //stack_padding!();
    modify_page_permissions(x, PROT_NONE);
}

pub fn normal_sc_u(x: i64) {
    stack_padding!();

    modify_page_permissions(x, PROT_READ | PROT_WRITE);
}


/*
Need a macro to record main function's page address. This is for securing all the pages starting from main.
*/

//static mut FRAMES: [i64; 30] = [0; 30];


#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn record_main(main_page: &mut i64) {
    let mut rbp = 0;
    unsafe {
                asm!("movq %rbp, $0
                  "
                  : "=r"(rbp)
                  : /* no inputs */
                  : "rbp");
              }
    *main_page = rbp;
}
