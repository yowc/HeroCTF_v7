use core::{
    arch::asm, ffi::c_void, mem::{size_of, transmute}, ptr::{copy_nonoverlapping, null_mut, read}, slice::from_raw_parts, str::from_utf8_unchecked
};

use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
#[allow(unused_imports)]
use windows_sys::Win32::{
    Foundation::{FARPROC, HMODULE, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP, EXCEPTION_BREAKPOINT},
    System::{
        Diagnostics::Debug::{
            IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_NT_HEADERS64,AddVectoredExceptionHandler, RemoveVectoredExceptionHandler,
            CONTEXT, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_CONTINUE_EXECUTION
        },
        SystemServices::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
        },
        Threading::{PEB, PEB_LDR_DATA},
        Memory::{HeapAlloc, GetProcessHeap, HeapFree, HEAP_ZERO_MEMORY},
    },
    UI::WindowsAndMessaging::MessageBoxA
};


#[allow(unused_imports)]
use crate::hash_macro::{const_random, hasher, HashSeed};
use crate::{debug_println, hash_it, types::{DllInfo, LdrDataTableEntry, TEB}};
use crate::utils::{utf8_from_utf16, get_cstr_len};

pub const OPCODE_SUB_RSP: u32 = 0xec8348;
pub const OPCODE_RET_CC: u16 = 0xccc3;
pub const OPCODE_RET: u8 = 0xc3;
pub const OPCODE_CALL: u8 = 0xe8;
pub const CALL_FIRST: u32 = 1;
pub const TRACE_FLAG: u32 = 0x100;
pub const OPCODE_SZ_ACC_VIO: u64 = 2;

pub const FIFTH_ARGUMENT: u64 = 0x8 * 0x5;

static mut NTDLL_INFO: DllInfo = DllInfo { base_address: 0, end_address: 0 };
pub static mut NTDLL_HANDLE: usize = 0;
static mut OPCODE_SYSCALL_OFF: u64 = 0;
static mut OPCODE_SYSCALL_RET_OFF: u64 = 0;
static mut H1: *mut c_void = null_mut();
static mut H2: *mut c_void = null_mut();
static mut SAVED_CONTEXT: *mut CONTEXT = core::ptr::null_mut();
static mut SYSCALL_ENTRY_ADDRESS: u64 = 0;
static mut IS_SUB_RSP: i32 = 0;
pub static mut SYSCALL_NO: u32 = 0;
pub static mut EXTENDED_ARGS: bool = false;
static mut HOOKS_READY: bool = false;
pub static mut ACTIVE_SYSCALL_ADDR: u64 = 0;  // Track which syscall we're currently hooking
static mut SAVED_STACK_ARGS: [u64; 8] = [0; 8];  // Buffer to hold stack parameters (5th-12th args)


#[macro_export]
macro_rules! syscall {
    ($syscall_hash:expr, $fn_sig:ty $(, $param:expr)*) => {
        unsafe {
            use core::mem::transmute;

            // Get ntdll handle from global static
            let h_module = $crate::syscall::NTDLL_HANDLE;

            if h_module == 0 {
                $crate::debug_println!("[!] NTDLL not initialized. Call initialize_hooks() first!");
                return Default::default();
            }

            // Resolve the system call's address and System Service Number (SSN).
            let (syscall_addr_opt, ssn) = $crate::syscall::getproc_address_ssn(h_module, $syscall_hash);

            // Exit if the SSN is invalid or address is `null`.
            if syscall_addr_opt.is_none() || ssn < 0 {
                $crate::debug_println!("[!] Unable to resolve syscall");
                return Default::default();
            }

            let syscall_addr = syscall_addr_opt.unwrap() as *mut u8;

            // Convert the resolved address to a function pointer of the specified type (`$fn_sig`).
            let pt_syscall: $fn_sig = transmute(syscall_addr);

            // Set up hardware breakpoints for this syscall
            // This will trigger an access violation that sets up Dr0/Dr1
            $crate::syscall::set_hw_bp(syscall_addr as usize, 1, ssn as u32);

            // Invoke the system call with the provided parameters (`$param`).
            // The hardware breakpoints will intercept this call and redirect through
            // demofunction, then execute the real syscall via stack spoofing.
            // The Dr1 handler restores RSP, allowing the natural 'ret' to return
            // to this point with RAX containing the actual NTSTATUS.
            pt_syscall($($param),*)
        }
    };
}

/// Retrieve a pointer to the current process PEB
fn get_peb() -> *mut PEB {
    let teb = get_teb();
    unsafe { (*teb).ProcessEnvironmentBlock }
}

/// Retrieve a pointer to the current process TEB
fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
        unsafe {
            asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
        };
    teb
}

/// Retrieve a module handle from a specific HashSeed or None if the module is not found
pub fn get_module_handle(hash_seed: HashSeed) -> Option<(usize, usize)> {
    let peb: *mut PEB = get_peb();

    unsafe {
        let ldr: *const PEB_LDR_DATA = (*peb).Ldr;

        let mut data_table_entry: *const LdrDataTableEntry =
            (*ldr).InMemoryOrderModuleList.Flink as *const LdrDataTableEntry;
        let mut utf8_array: [u8; 260] = [0; 260];
        let mut count = 0;

        while !data_table_entry.is_null() {
            count += 1;

            let module_name_ptr: *mut u16 = (*data_table_entry).FullDllName.Buffer;
            let module_name_len: usize = ((*data_table_entry).FullDllName.Length / 2) as usize;


            // Sanity check: module name length should be reasonable (< 260 characters)
            if module_name_len == 0 || module_name_len > 260 || module_name_ptr.is_null() {

                // Move to next entry
                let next_entry = (*data_table_entry).InMemoryOrderLinks.Flink as *const LdrDataTableEntry;
                if next_entry == data_table_entry {
                    break;
                }
                data_table_entry = next_entry;

                if count > 100 {
                    break;
                }
                continue;
            }

            utf8_from_utf16(module_name_ptr, module_name_len, &mut utf8_array);

            let current_hash = hasher(&utf8_array[0..module_name_len], hash_seed.seed);

            if current_hash == hash_seed.hash {
                debug_println!("[*] Found matching module!");
                let h_module: usize = (*data_table_entry).in_initilization_order_links as usize;
                let dos_header: *const IMAGE_DOS_HEADER = h_module as *const IMAGE_DOS_HEADER;
                if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                    return None;
                }
                let image_nt_header = h_module + (*dos_header).e_lfanew as usize;
                let nt_header: *const IMAGE_NT_HEADERS64 = image_nt_header as *const IMAGE_NT_HEADERS64;

                if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                    return None;
                }
                let size_of_image: usize = (*nt_header).OptionalHeader.SizeOfImage as usize;

                return Some((h_module, size_of_image));
            }

            let next_entry = (*data_table_entry).InMemoryOrderLinks.Flink as *const LdrDataTableEntry;

            // Check for circular reference
            if next_entry == data_table_entry {
                break;
            }

            data_table_entry = next_entry;

            // Safety check to prevent infinite loop
            if count > 100 {
                break;
            }
        }

        debug_println!("[!] Module not found after checking {} modules", count);
    }
    return None;
}

/// Retrieve a FARPROC inside a module from a specific HashSeed
pub fn getproc_address_ssn(h_module: usize, hash_seed: HashSeed) -> (FARPROC, i32) {
    unsafe {
        if h_module == 0 {
            return (None, 0);
        }
        let h_module: usize = h_module as usize;
        let dos_header: *const IMAGE_DOS_HEADER = h_module as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return (None, 0);
        }
        let image_nt_header = h_module + (*dos_header).e_lfanew as usize;

        let nt_header: *const IMAGE_NT_HEADERS64 = image_nt_header as *const IMAGE_NT_HEADERS64;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return (None, 0);
        }
        let data_directory: *const IMAGE_DATA_DIRECTORY = (&(*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize])
            as *const IMAGE_DATA_DIRECTORY;
        let p_image_export_dir: usize = h_module + ((*data_directory).VirtualAddress as usize);

        let image_export_dir: *const IMAGE_EXPORT_DIRECTORY =
            p_image_export_dir as *const IMAGE_EXPORT_DIRECTORY;

        // Base addresses for the export tables
        let function_name_array_base: usize = h_module + ((*image_export_dir).AddressOfNames) as usize;
        let function_pointer_array_base: usize =
            h_module + ((*image_export_dir).AddressOfFunctions) as usize;
        let function_ordinal_array_base: usize =
            h_module + ((*image_export_dir).AddressOfNameOrdinals) as usize;

        let mut ssn: i32 = -1;  // Start at -1 so first syscall gets SSN 0
        for i in 0..(*image_export_dir).NumberOfNames {
            // Get the name offset from the name array
            let name_offset: u32 = *((function_name_array_base + (i as usize * size_of::<u32>())) as *const u32);
            let p_function_name: *const u8 = (h_module + (name_offset as usize)) as *const u8;
            let current_function_name_len = get_cstr_len(p_function_name);
            let function_name = from_raw_parts(p_function_name, current_function_name_len);
            let function_name_str = from_utf8_unchecked(function_name);

            // Check if this is a Zw* syscall function
            // Note: Only count Zw* functions because Nt* and Zw* pairs share the same SSN
            // and Zw* functions are listed first in alphabetical order
            let is_syscall = function_name_str.starts_with("Zw");

            // Increment SSN counter BEFORE checking for hash match
            // This ensures the matched function gets the correct SSN
            if is_syscall {
                ssn += 1;
            }

            let current_function_hash = hasher(function_name, hash_seed.seed);

            if current_function_hash == hash_seed.hash {
                // Get the ordinal for this function name
                let ordinal: u16 = *((function_ordinal_array_base + (i as usize * size_of::<u16>())) as *const u16);


                // Use the ordinal to index into the function pointer array
                let fp_offset = *((function_pointer_array_base + (ordinal as usize * size_of::<u32>())) as *const u32);
                let current_function_pointer: FARPROC = transmute(h_module + (fp_offset as usize));

                // Extract SSN from the function bytes
                // Windows syscall stubs follow this pattern:
                // mov r10, rcx       ; 4C 8B D1
                // mov eax, SSN       ; B8 [SSN as 4 bytes]
                // ...
                let func_addr = h_module + (fp_offset as usize);
                let extracted_ssn = if read((func_addr + 3) as *const u8) == 0xB8 {
                    // Read the 4-byte SSN value after the 0xB8 opcode
                    read((func_addr + 4) as *const u32) as i32
                } else {
                    ssn  // Fallback to counted SSN if pattern doesn't match
                };

                return (current_function_pointer, extracted_ssn);
            }
        }
        return (None, 0);
    } 
}


/// Example function designed to maintain a clean call stack.
/// This function can be modified to call different legitimate Windows APIs.
pub unsafe extern "C" fn demofunction() {
    unsafe { MessageBoxA(null_mut(), null_mut(), null_mut(), 0); };
}

pub fn initialize_dll_info(hash_seed: HashSeed) -> DllInfo{
    let mut obj: DllInfo = DllInfo { base_address: 0, end_address: 0 };
    let (base_addr, size_of_image) = match get_module_handle(hash_seed) {
        Some(tuple) => tuple,
        _ => return obj,
    };

    obj.base_address = base_addr;
    obj.end_address =  base_addr + size_of_image;
    obj
}

/// Adds hardware breakpoints at the syscall entry and return addresses.
///
/// This function is triggered when an `EXCEPTION_ACCESS_VIOLATION` occurs. It identifies the syscall
/// opcode by scanning the instruction pointer (Rcx) for the `syscall` instruction, then sets
/// hardware breakpoints (Dr0 and Dr1) at the syscall entry and return addresses, allowing for
/// interception and manipulation of the syscall.
#[unsafe(no_mangle)]
unsafe extern "system" fn AddHwBp(exception_info: *mut  EXCEPTION_POINTERS) -> i32 {
    unsafe {
        // Don't process exceptions if hooks aren't ready yet
        if !HOOKS_READY {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let exception_info = &*exception_info;

        // Check if the exception is an access violation
        if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
            // Only process if we have an active syscall to hook
            if ACTIVE_SYSCALL_ADDR == 0 {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Set the syscall entry address to the current RCX register value
            SYSCALL_ENTRY_ADDRESS = (*exception_info.ContextRecord).Rcx;

            // Only hook if this matches our active syscall address
            if SYSCALL_ENTRY_ADDRESS != ACTIVE_SYSCALL_ADDR {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Scan for the syscall opcode (0x0F 0x05) in the instruction sequence
            for i in 0..25 {
                if read((SYSCALL_ENTRY_ADDRESS + i) as *const u8) == 0x0F
                    && read((SYSCALL_ENTRY_ADDRESS + i + 1) as *const u8) == 0x05
                {
                    OPCODE_SYSCALL_OFF = i as u64;
                    OPCODE_SYSCALL_RET_OFF = i as u64 + 2;
                    break;
                }
            }

            // Set Dr0 to the syscall entry address and enable the hardware breakpoint
            (*exception_info.ContextRecord).Dr0 = SYSCALL_ENTRY_ADDRESS;
            (*exception_info.ContextRecord).Dr7 |= 1 << 0;

            // Set Dr1 to monitor the syscall return address
            (*exception_info.ContextRecord).Dr1 = SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_RET_OFF;
            (*exception_info.ContextRecord).Dr7 |= 1 << 2;

            (*exception_info.ContextRecord).Rip += OPCODE_SZ_ACC_VIO;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EXCEPTION_CONTINUE_SEARCH
    }
}

/// Handles hardware breakpoints and single-step exceptions for syscall interception.
///
/// This function is triggered by `EXCEPTION_SINGLE_STEP` and checks for two key conditions:
/// 1. A hit on the syscall entry breakpoint (Dr0).
/// 2. A hit on the syscall return breakpoint (Dr1).
/// Additionally, it traces and handles the instruction flow within `ntdll.dll`, emulating
/// syscalls and restoring context as necessary.
///
/// - Clears and disables hardware breakpoints when hit.
/// - Saves and restores context for syscall interception.
/// - Emulates syscalls by manipulating the instruction pointer (Rip) and registers.
#[allow(static_mut_refs)]
#[unsafe(no_mangle)]
unsafe extern "system" fn HandlerHwBp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        // Don't process exceptions if hooks aren't ready yet
        if !HOOKS_READY {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let exception_info = &*exception_info;

        // Check if the exception is due to a single-step event (hardware breakpoint hit)
        if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            // Handle syscall hardware breakpoint (entry point)
            if (*exception_info.ExceptionRecord).ExceptionAddress
                == (SYSCALL_ENTRY_ADDRESS as *mut c_void)
            {

                // Reset the state machine for stack frame detection
                IS_SUB_RSP = 0;

                // Disable Dr0 (syscall entry breakpoint)
                (*exception_info.ContextRecord).Dr0 = 0;
                (*exception_info.ContextRecord).Dr7 &= !(1 << 0);

                // Save the current CPU context
                copy_nonoverlapping(exception_info.ContextRecord, SAVED_CONTEXT, 1);

                // Save the stack parameters (5th-12th args) before they get overwritten
                let rsp = (*exception_info.ContextRecord).Rsp;
                copy_nonoverlapping(
                    (rsp + FIFTH_ARGUMENT) as *const u64,
                    SAVED_STACK_ARGS.as_mut_ptr(),
                    8,
                );

                // Redirect execution to a demo function after storing the context
                (*exception_info.ContextRecord).Rip = demofunction as u64;

                // Set the trace flag to continue tracing
                (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Handle syscall return (Dr1 breakpoint)
            else if (*exception_info.ExceptionRecord).ExceptionAddress
                == (SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_RET_OFF) as *mut c_void
            {
                // Disable Dr1 (return breakpoint)
                (*exception_info.ContextRecord).Dr1 = 0;
                (*exception_info.ContextRecord).Dr7 &= !(1 << 2);

                // Restore the saved stack pointer
                // The natural 'ret' instruction at the current RIP will execute
                // and return to the caller with RAX preserved
                (*exception_info.ContextRecord).Rsp = (*SAVED_CONTEXT).Rsp;

                // Clear the active syscall address so we're not hooking anymore
                ACTIVE_SYSCALL_ADDR = 0;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Handle tracing within `ntdll.dll`
            else if (*exception_info.ContextRecord).Rip >= NTDLL_INFO.base_address as u64
                && (*exception_info.ContextRecord).Rip <= NTDLL_INFO.end_address as u64
            {
                // Look for a "sub rsp" instruction to detect the stack frame
                if IS_SUB_RSP == 0 {
                    for i in 0..80 {
                        let opcode_ret_cc =
                            read(((*exception_info.ContextRecord).Rip + i as u64) as *const u16);

                        if opcode_ret_cc == OPCODE_RET_CC {
                            break;
                        }
                        let opcode_sub_rsp =
                            read(((*exception_info.ContextRecord).Rip + i as u64) as *const u32);

                        if (opcode_sub_rsp & 0xffffff) == OPCODE_SUB_RSP {
                            if (opcode_sub_rsp >> 24) >= 0x58 {
                                // Stack frame detected
                                IS_SUB_RSP = 1;
                                (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                                return EXCEPTION_CONTINUE_EXECUTION;
                            } else {
                                break;
                            }
                        }
                    }
                }

                // Wait for a "call" instruction to continue processing
                if IS_SUB_RSP == 1 {
                    let rip_value = read((*exception_info.ContextRecord).Rip as *const u16);
                    if rip_value == OPCODE_RET_CC || rip_value as u8 == OPCODE_RET {
                        IS_SUB_RSP = 0;
                    } else if rip_value as u8 == OPCODE_CALL {
                        IS_SUB_RSP = 2;
                        (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }

                // Handle stack frame and call instruction
                if IS_SUB_RSP == 2 {
                    IS_SUB_RSP = 0;
                    // Save the current RSP (we're deep in ntdll's call stack)
                    let temp_rsp = (*exception_info.ContextRecord).Rsp;

                    // Restore the saved context (this includes the original register parameters)
                    copy_nonoverlapping(
                        SAVED_CONTEXT,
                        exception_info.ContextRecord as *mut CONTEXT,
                        1,
                    );

                    // Use the current RSP (not the saved one) so we don't corrupt the stack
                    (*exception_info.ContextRecord).Rsp = temp_rsp;

                    // Emulate the syscall by setting registers and instruction pointer
                    (*exception_info.ContextRecord).R10 = (*exception_info.ContextRecord).Rcx;
                    (*exception_info.ContextRecord).Rax = SYSCALL_NO as u64;
                    (*exception_info.ContextRecord).Rip = SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_OFF;

                    // Handles extended arguments for syscalls with more than 4 up to a maximum of 12 arguments.
                    // Copy the saved stack arguments to the current stack location.
                    if EXTENDED_ARGS {
                        let current_rsp = (*exception_info.ContextRecord).Rsp;

                        // debug_println!("[*] Restoring saved stack args to {:#x}",
                        //     current_rsp + FIFTH_ARGUMENT);

                        // Copy the saved stack arguments from our buffer to the current stack
                        copy_nonoverlapping(
                            SAVED_STACK_ARGS.as_ptr(),
                            (current_rsp + FIFTH_ARGUMENT) as *mut u64,
                            8,
                        );

                    }

                    // Clear the trace flag after handling the syscall
                    (*exception_info.ContextRecord).EFlags &= !TRACE_FLAG;

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // Continue tracing
            (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EXCEPTION_CONTINUE_SEARCH
    }
}


/// Initializes the necessary hooks for syscall interception.
///
/// This function sets up two vectored exception handlers (`AddHwBp` and `HandlerHwBp`) for adding
/// and handling hardware breakpoints. It allocates memory for saving the CPU context and initializes
/// information about `ntdll.dll` (base address and end address) for use in syscall tracing.
#[allow(static_mut_refs)]
pub fn initialize_hooks() {
    unsafe {
        debug_println!("[*] Step 1: Adding vectored exception handlers...");

        // Add vectored exception handlers for system call handling
        H1 = AddVectoredExceptionHandler(CALL_FIRST, Some(AddHwBp));
        H2 = AddVectoredExceptionHandler(CALL_FIRST, Some(HandlerHwBp));

        debug_println!("[*] Step 2: Allocating memory for context...");

        // Allocate memory for saving the CPU context during exception handling
        SAVED_CONTEXT = HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            size_of::<CONTEXT>(),
        ) as *mut CONTEXT;

        debug_println!("[*] Step 3: Initializing ntdll.dll info...");

        // Initialize ntdll.dll base and end addresses for syscall tracing
        NTDLL_INFO = initialize_dll_info(hash_it!("ntdll.dll"));
        if NTDLL_INFO.base_address == 0 {
            debug_println!("[!] Failed to find ntdll.dll!");
            return;
        }

        // Store ntdll handle in global static for use by syscall macro
        NTDLL_HANDLE = NTDLL_INFO.base_address;

        debug_println!("[*] Hooks initialized successfully");
        debug_println!("[*] Ntdll Handle: {:#x}", NTDLL_HANDLE);
        debug_println!("[*] Ntdll Start Address: {:#x}", NTDLL_INFO.base_address);
        debug_println!("[*] Ntdll End Address: {:#x}", NTDLL_INFO.end_address);

        // Mark hooks as ready - this MUST be the last step
        // Any debug output AFTER this might trigger unexpected behavior
        HOOKS_READY = true;

        debug_println!("[*] HOOKS_READY set to true");
    }
}

/// Cleans up the exception hooks by removing the previously added handlers.
///
/// This function checks if the exception handlers (`H1` and `H2`) were added, and if so,
/// it removes them using `RemoveVectoredExceptionHandler`.
pub fn destroy_hooks() {
    unsafe {
        // Disable hooks first to prevent any more exceptions from being processed
        HOOKS_READY = false;
    }

    debug_println!("\n\n[*] Cleaning up the hooks");

    unsafe {
        if !H1.is_null() {
            RemoveVectoredExceptionHandler(H1);
        }

        if !H2.is_null() {
            RemoveVectoredExceptionHandler(H2);
        }
        if !SAVED_CONTEXT.is_null() {
            HeapFree(GetProcessHeap(), 0, SAVED_CONTEXT as *const c_void);
        }
    }
}

/// This function triggers an access violation exception to force the system to raise an exception.
/// IMPORTANT: RCX must be set to the syscall address before the exception occurs
#[allow(unused_variables)]
pub fn set_hw_bp(func_address: usize, flag: i32, ssn: u32) {
    unsafe {
        EXTENDED_ARGS = flag != 0;
        SYSCALL_NO = ssn;
        ACTIVE_SYSCALL_ADDR = func_address as u64;

        // debug_println!("[*] Setting up hardware BP for address: {:#x}", func_address);
        trigger_access_violation_exception(func_address);
        // debug_println!("[*] Hardware BP setup complete");
    }
}

/// This function dereferences a null pointer, which causes an access violation and is used to
/// invoke the previously set vectored exception handlers.
/// The syscall_addr is passed as a parameter and we ensure RCX has it when the exception occurs.
#[inline(never)]
fn trigger_access_violation_exception(syscall_addr: usize) {
    unsafe {
        // On Windows x64, first parameter arrives in RCX
        // We load it explicitly and then immediately trigger the exception
        // This ensures RCX contains syscall_addr when AddHwBp reads it
        asm!(
            // Load the syscall address into RCX explicitly
            "mov rcx, {addr}",
            // Trigger access violation by writing to null pointer
            "xor rax, rax",
            "mov byte ptr [rax], al",
            addr = in(reg) syscall_addr,
            lateout("rcx") _,
            lateout("rax") _,
        );
    }
}