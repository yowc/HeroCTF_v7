use windows_sys::Win32::System::Console::{GetStdHandle, WriteConsoleW, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;

// Helper to write to console
#[allow(dead_code)]
pub fn print_console(s: &str) {
    let utf16: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if !handle.is_null() && handle as isize != -1 {
            let mut written = 0u32;
            WriteConsoleW(
                handle,
                utf16.as_ptr(),
                utf16.len() as u32,
                &mut written,
                core::ptr::null_mut(),
            );
        }
    }
}

// Small helper to send UTF-16 strings to OutputDebugStringW (for debuggers only)
#[allow(dead_code)]
pub fn output_debug_string(s: &str) {
    // Convert to UTF-16 with null terminator
    let mut utf16: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    utf16.push(0);
    unsafe {
        OutputDebugStringW(utf16.as_mut_ptr());
    }
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        let _ = write!(&mut s, $($arg)*);
        $crate::print_no_std::print_console(&s);
    });
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_println {
    () => ({
        $crate::print_no_std::print_console("\n");
    });
    ($fmt:expr) => ({
        $crate::print_no_std::print_console(concat!($fmt, "\n"));
    });
    ($fmt:expr, $($arg:tt)*) => ({
        $crate::debug_print!(concat!($fmt, "\n"), $($arg)*);
    });
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {{}};
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {{}};
}
