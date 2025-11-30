use core::ffi::c_void;
use windows_sys::Win32::{
    Foundation::{HMODULE, UNICODE_STRING},
    System::{Kernel::LIST_ENTRY, Threading::PEB, WindowsProgramming::LDR_DATA_TABLE_ENTRY_0},
};
/// Custom LDR_DATA_TABLE_ENTRY structure to ease the cast of the in_initilization_order_links
/// field
#[allow(dead_code)] // because some fields are not used
#[allow(non_snake_case)]
#[repr(C)]
pub struct LdrDataTableEntry {
    pub Reserved1: [c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: *mut c_void,
    pub in_initilization_order_links: HMODULE,
    pub padding: *mut c_void,
    pub DllBase: *mut c_void,
    pub Reserved3: [*mut c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 3],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: u32,
}


#[allow(non_snake_case)]
#[repr(C)]
pub struct TEB {
    Reserved1: [*mut c_void; 12],
    pub ProcessEnvironmentBlock: *mut PEB,
    Reserved2: [*mut c_void; 399],
    Reserved3: [u8; 1952],
    TlsSlots: [*mut c_void; 64],
    Reserved4: [u8; 8],
    Reserved5: [*mut c_void; 26],
    ReservedForOle: *mut c_void,
    Reserved6: [*mut c_void; 4],
    TlsExpansionSlots: *mut c_void,
}

#[repr(C)]
pub struct DllInfo {
    pub base_address: usize,
    pub end_address: usize,
}