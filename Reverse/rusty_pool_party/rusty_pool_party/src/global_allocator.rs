use alloc::alloc::{GlobalAlloc, Layout};

use core::ffi::c_void;
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree, HeapReAlloc,
};

pub struct CustomAllocator;

unsafe impl GlobalAlloc for CustomAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        (unsafe { HeapAlloc(GetProcessHeap(), 0, _layout.size()) }) as *mut u8
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        (unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()) }) as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        unsafe { HeapFree(GetProcessHeap(), 0, _ptr as *mut c_void) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        (unsafe {
            HeapReAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                ptr as *mut c_void,
                new_size,
            )
        }) as *mut u8
    }
}
