
pub use core;

/*
    This is a secure stack struct that contains and is capable of securing access to specific data items represented by the variable item. This variable can hold any stack allocated value and can be as large as a complete VM page. Two arrays wrap item so it's surely outside any other stack page that might not hold similar security properties.

pub struct SecureStack<T> {
    #[allow(dead_code)]
    p1: core::Padding,
    pub pageaddr: usize,
    pub item: T,
    #[allow(dead_code)]
    p2: core::Padding,
}*/

/*
    To use SecureStack, programmers will simply invoke SecureStack::new and pass the required item. Note that if the item is a heap allocated object, only the reference to the heap object can be protected.

    To impose security properties, either use private (for making the page unaccessible at all), immutable (for making the page read only), and mutable (for releasing any read/write restriction but restricting execution).


impl<T> SecureStack<T> {
    pub fn new(i: T) -> SecureStack<T> {
        SecureStack {
            p1: Default::default(),
            pageaddr: memory_page_addr_usize!(i),
            item: i,
            p2: Default::default(),
        }
    }
    pub fn private(&self) {
        core::private_single_stack_page(&(*self).item);
    }
    pub fn immutable(&self) {
        core::immutable_single_stack_page(&(*self).item);
    }
    pub fn mutable(&self) {
        core::mutable_single_stack_page(&(*self).item);
    }
}*/
