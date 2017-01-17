use libc::mprotect;
use libc::PROT_READ;
use libc::PROT_WRITE;
use libc::PROT_NONE;
use libc::c_void;
use rand::random;
use std::fmt;

const P_DEFAULT: usize = 1200;

#[allow(dead_code)]
pub struct Padding {
    pub space: [i64; P_DEFAULT]
}

impl Default for Padding {
    fn default() -> Padding { Padding {space: [0; P_DEFAULT]} }
}

impl fmt::Debug for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Padding")
    }
}

#[allow(dead_code)]
pub struct PaddingHalf {
    pub space: [i64; P_DEFAULT/2]
}

impl Default for PaddingHalf {
    fn default() -> PaddingHalf { PaddingHalf {space: [0; P_DEFAULT/2]} }
}

#[macro_export]
macro_rules! memory_page_addr {
    ($x:expr) => (((&$x as *const _) as i64) & !(4095));
}

#[macro_export]
macro_rules! memory_page_addr_usize {
    ($x:expr) => ( (((&$x as *const _) as i64) & !(4095)) as usize );
}

#[macro_export]
macro_rules! print_memory_addr {
    ($x:expr, $y:expr) => (println!("{:} address: {:?} at page 0x{:X}", $y, &$x as *const _, ((&$x as *const _) as i64) & !(4095)));
}

/*
We'll define a special type for storing the kernel key on stack.
We need this type for performing operations like drop to make sure protections are released when going out of scope.
*/
pub struct FcKernelKey {
    pub key: usize
}
/*
This will generate a key by simply using the rand crate. A better key generation algorithm should be used, later on.
*/
impl Default for FcKernelKey {
    fn default() -> FcKernelKey { FcKernelKey {key: random::<usize>()} }
}
/*
We'll probably need to implement some drop, but nothing for now.
*/
impl Drop for FcKernelKey {
    fn drop(&mut self) {
    }
}

/*
A macro that will do the key generation by calling the default function and then returning the actual key.
*/
#[macro_export]
macro_rules! get_kernel_key {
    () => (
    	FcKernelKey::default().key
    );
}

/*
This function receives a pointer to one of the bindings
on a stack page. It will compute the start address of the page and will attempt to set the page to read only. The challenge is to avoid possible crashes because of wrong page numbering or because the page may be used in the future. For now, it will assume the page can safely be protected. Avoid calling other functions or introducing new bindings as much as possible, except for mprotect and the padding requirement, of course.
*/
pub fn immutable_single_stack_page<T>(x: &T) {
    unsafe {
        mprotect( (((x as *const _) as i64) & !(4095)) as *mut c_void, 4096, PROT_READ );
    }
}

/*
Same as immutable_single_stack_page but sets the page permission to NONE. No one can use the page.
*/
pub fn private_single_stack_page<T>(x: &T) {
    unsafe {
        mprotect( (((x as *const _) as i64) & !(4095)) as *mut c_void, 4096, PROT_NONE );
    }
}

/*
Same as private_single_stack_page but without giving a pointer to the variable. Instead, pass the address to the "PAGE" directly.
*/
pub fn private_single_stack_page_with_addr(addr: usize) {
    unsafe {
        mprotect( addr as *mut c_void, 4096, PROT_NONE );
    }
}


/*
Macros to facilitate calls to the functions for changing access to stack pages.
*/

#[macro_export]
macro_rules! immutable_stack {
    ($x:expr) => (
        let p_x98d7: Padding = Default::default();
        immutable_single_stack_page(&$x);
    );
}

#[macro_export]
macro_rules! private_stack {
    ($x:expr) => (
        let p_x98d7: Padding = Default::default();
        private_single_stack_page(&$x);
    );
}

/*
This function will reverse the effect of the previous functions.
*/

pub fn mutable_single_stack_page<T>(x: &T) {
    unsafe {
        mprotect( (((x as *const _) as i64) & !(4095)) as *mut c_void, 4096, PROT_READ | PROT_WRITE);
    }
}

/*
The previous one may crash when restroing a PROT_NONE page.
*/
pub fn mutable_single_stack_page_with_addr(addr: usize) {
    unsafe {
        mprotect( addr as *mut c_void, 4096, PROT_READ | PROT_WRITE);
    }
}

#[macro_export]
macro_rules! mutable_stack {
    ($x:expr) => (
        mutable_single_stack_page(&$x);
    );
}

#[macro_export]
macro_rules! protect_stack {
    ($x:expr,$y:expr) => (
    	$y = get_kernel_key!();
    	let page = memory_page_addr_usize!($x);
    	immutable_stack!($x);
        disable_mprotect_stack(&$y, &page);
    );
}

#[macro_export]
macro_rules! free_stack {
    ($x:expr,$y:expr) => (
    	enable_mprotect_stack(&$y);
    	mutable_stack!($x);
    );
}


/*
This function will request a ban on mprotect using a key that is stored
on stack. Note that if the stack is read only at this point, this function
will fail. We'll have to find a way to check for stack protection at this point.
start holds the key, len holds the first page under protection, and prot holds a signal value that indicates the request from the kernel module.
*/

pub fn disable_mprotect_stack(key: &usize, pageaddr: &usize) {
    let prot = 0x00A00A00C; //Request ID --disable mprotet
    let len: usize = *pageaddr;
    unsafe {
        mprotect((*key) as *mut c_void, len, prot );
    }
}

pub fn enable_mprotect_stack(key: &usize) {
    let prot = 0x00A00A00D; //Request ID --enable mprotet
    let len: usize = 0;
    unsafe {
        mprotect((*key) as *mut c_void, len, prot );
    }
}

/*
Protect more pages by requesting the kernel module to do so. Additional page address will be passed using a failed mprotect call which has no side effects.
*/
pub fn additional_pages_mprotect(key: &usize,addr: &usize) {
    let prot = 0x00A00A00B; //Request ID --enable mprotet
    let len = *addr;
    unsafe {
        mprotect((*key) as *mut c_void, len, prot );
    }
}
