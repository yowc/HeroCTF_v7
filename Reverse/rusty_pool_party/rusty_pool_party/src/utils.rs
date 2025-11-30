/// XOR-obfuscated string with compile-time encryption and runtime decryption
/// Uses a random 1-byte XOR key generated at compile time
/// Returns &'static str directly
#[macro_export]
macro_rules! obfstr {
    ($str:expr) => {{
        use const_random::const_random;
        use core::sync::atomic::{AtomicBool, Ordering};

        const XOR_KEY: u8 = const_random!(u8);
        const INPUT: &str = $str;
        const LEN: usize = INPUT.len();

        // Compile-time XOR encryption
        const fn xor_encrypt() -> [u8; LEN] {
            let bytes = INPUT.as_bytes();
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = bytes[i] ^ XOR_KEY;
                i += 1;
            }
            result
        }

        const ENCRYPTED: [u8; LEN] = xor_encrypt();

        // Runtime decryption with lazy initialization
        static mut DECRYPTED: [u8; LEN] = [0u8; LEN];
        static INITIALIZED: AtomicBool = AtomicBool::new(false);

        unsafe {
            if !INITIALIZED.load(Ordering::Relaxed) {
                let ptr = core::ptr::addr_of_mut!(DECRYPTED);
                let mut i = 0;
                while i < LEN {
                    (*ptr)[i] = ENCRYPTED[i] ^ XOR_KEY;
                    i += 1;
                }
                INITIALIZED.store(true, Ordering::Relaxed);
            }
            let ptr = core::ptr::addr_of!(DECRYPTED);
            core::str::from_utf8_unchecked(core::slice::from_raw_parts((*ptr).as_ptr(), LEN))
        }
    }};
}

/// Macro to create a null-terminated UTF-16 array from a string literal at compile time
#[macro_export]
macro_rules! utf16_str {
    ($str:expr) => {{
        const STR: &str = $str;
        const LEN: usize = STR.len();
        const fn utf16_encode() -> [u16; LEN + 1] {
            let bytes = STR.as_bytes();
            let mut result = [0u16; LEN + 1];
            let mut i = 0;
            while i < LEN {
                result[i] = bytes[i] as u16;
                i += 1;
            }
            result[LEN] = 0; // null terminator
            result
        }
        utf16_encode()
    }};
}

pub fn get_cstr_len(cstring: *const u8) -> usize {
    let mut string_ptr: usize = cstring as usize;
    unsafe {
        while *(string_ptr as *const u8) != 0 {
            string_ptr += 1;
        }
    }
    string_ptr - cstring as usize
}

// also lower_case every chr
pub fn utf8_from_utf16(wide_string: *mut u16, wide_string_len: usize, utf8_array: &mut [u8]) {
    let wide_string_ptr: usize = wide_string as usize;
    let mut current_chr: u8;
    for i in 0..wide_string_len {
        unsafe { current_chr = *((wide_string_ptr + i * 2) as *const u16) as u8; }
        if (current_chr > 64) && (current_chr < 91) {
            current_chr += 32;
        }
        utf8_array[i] = current_chr;
    }
}