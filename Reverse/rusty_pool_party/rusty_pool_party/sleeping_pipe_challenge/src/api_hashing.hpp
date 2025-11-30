#ifndef _API_HASHING_H
#define _API_HASHING_H

#include <stdint.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include "utils.hpp"
#include "config_type.hpp"
#include "compile_time_hash.hpp"

// Logging macros - disabled in release builds
#ifndef VERBOSE
#define DEBUG(...)
#define INFO(...)
#define INFO_SUCCESS(...)
#define ERROR_LOG(...)
#endif

typedef uint32_t hash_t;

uint64_t get_proc_address(HMODULE module_handle, hash_t function_hash);
HMODULE get_module_handle(hash_t module_hash);
hash_t get_crc32(uint8_t *data, uint32_t data_size);
hash_t get_fnv32a(uint8_t *data, uint32_t data_size);


#define FNV_32_PRIME ((hash_t)0x01000193)
#define HASH_IT get_fnv32a
#define UTF8_BUFFER_SIZE 1024

// ========================================
// COMPILE-TIME MODULE NAME HASHES
// ========================================
// Usage: get_module_handle(HASH_KERNEL32)
#define HASH_KERNEL32     HASH_W(L"kernel32.dll")
#define HASH_NTDLL        HASH_W(L"ntdll.dll")
#define HASH_USER32       HASH_W(L"user32.dll")
#define HASH_ADVAPI32     HASH_W(L"advapi32.dll")
#define HASH_WINHTTP      HASH_W(L"winhttp.dll")
#define HASH_SHELL32      HASH_W(L"shell32.dll")
#define HASH_GDI32        HASH_W(L"gdi32.dll")
#define HASH_WINMM        HASH_W(L"winmm.dll")

// ========================================
// COMPILE-TIME API NAME HASHES
// ========================================


// Function used in multiple file
// 
typedef BOOL (WINAPI* fnWriteFile)(
  HANDLE file,
  void *buffer,
  uint32_t number_of_bytes_to_write,
  uint32_t *number_of_bytes_written,
  LPOVERLAPPED overlapped
);

typedef HANDLE (WINAPI* fnCreateThread)(
  LPSECURITY_ATTRIBUTES thread_attributes,
  size_t stack_size,
  LPTHREAD_START_ROUTINE start_address,
  void *parameter,
  uint32_t creation_flags,
  uint32_t *thread_id
);

typedef uint32_t (WINAPI* fnWaitForSingleObject)(
  HANDLE handle,
  uint32_t milliseconds
);

typedef BOOL (WINAPI* fnCloseHandle)(
  HANDLE object
);

typedef BOOL (WINAPI* fnPostThreadMessageA)(
  uint32_t thread_id,
  uint32_t msg,
  WPARAM w_param,
  LPARAM l_param
);

typedef BOOL (WINAPI* fnGetExitCodeThread)(
  HANDLE thread,
  uint32_t *exit_code
);

typedef BOOL (WINAPI* fnGetMessageA)(
  LPMSG msg,
  HWND wnd,
  uint32_t msg_filter_min,
  uint32_t msg_filter_max
);

typedef HANDLE (WINAPI* fnCreateFileMappingW)(
  HANDLE file,
  LPSECURITY_ATTRIBUTES file_mapping_attributes,
  uint32_t protect,
  uint32_t maxium_size_high,
  uint32_t maxium_size_low,
  wchar_t *name
);

typedef void* (WINAPI* fnMapViewOfFile)(
  HANDLE file_mapping_object,
  uint32_t desired_access,
  uint32_t file_offset_high,
  uint32_t file_offset_low,
  size_t number_of_bytes_to_map
);

typedef BOOL (WINAPI* fnFreeLibrary)(
  HMODULE lib_module
);

typedef void (WINAPI* fnRtlEnterCriticalSection)(
  LPCRITICAL_SECTION critical_section
);

typedef void (WINAPI* fnRtlLeaveCriticalSection)(
  LPCRITICAL_SECTION critical_section
);

typedef void (WINAPI* fnRtlDeleteCriticalSection)(
  LPCRITICAL_SECTION critical_section
);

typedef void (WINAPI* fnRtlInitializeCriticalSection)(
  LPCRITICAL_SECTION critical_section
);

typedef BOOL (WINAPI* fnSetEvent)(
  HANDLE event
);

typedef HANDLE (WINAPI* fnHeapCreate)(
  uint32_t options,
  size_t initial_size,
  size_t maximum_size
);

typedef BOOL (WINAPI* fnHeapDestroy)(
  HANDLE heap
);

typedef void (WINAPI* fnExitThread)(
  uint32_t exit_code
);

// Named Pipe API
typedef HANDLE (WINAPI* fnCreateNamedPipeA)(
  const char* pipe_name,
  uint32_t open_mode,
  uint32_t pipe_mode,
  uint32_t max_instances,
  uint32_t out_buffer_size,
  uint32_t in_buffer_size,
  uint32_t default_timeout,
  LPSECURITY_ATTRIBUTES security_attributes
);

typedef BOOL (WINAPI* fnConnectNamedPipe)(
  HANDLE pipe,
  LPOVERLAPPED overlapped
);

typedef BOOL (WINAPI* fnDisconnectNamedPipe)(
  HANDLE pipe
);

typedef BOOL (WINAPI* fnReadFile)(
  HANDLE file,
  void* buffer,
  uint32_t number_of_bytes_to_read,
  uint32_t* number_of_bytes_read,
  LPOVERLAPPED overlapped
);

typedef HANDLE (WINAPI* fnCreateFileA)(
  const char* file_name,
  uint32_t desired_access,
  uint32_t share_mode,
  LPSECURITY_ATTRIBUTES security_attributes,
  uint32_t creation_disposition,
  uint32_t flags_and_attributes,
  HANDLE template_file
);

// File API
typedef uint32_t (WINAPI* fnGetFileSize)(
  HANDLE file,
  uint32_t* file_size_high
);

typedef BOOL (WINAPI* fnSetFilePointer)(
  HANDLE file,
  int32_t distance_to_move,
  int32_t* distance_to_move_high,
  uint32_t move_method
);

// ========================================
// NTDLL API HASHES
// ========================================
#define RTLINITIALIZECRITICALSECTION  HASH("RtlInitializeCriticalSection")
#define RTLENTERCRITICALSECTION       HASH("RtlEnterCriticalSection")
#define RTLLEAVECRITICALSECTION       HASH("RtlLeaveCriticalSection")
#define RTLDELETECRITICALSECTION      HASH("RtlDeleteCriticalSection")
#define RTLALLOCATEHEAP               HASH("RtlAllocateHeap")
#define RTLREALLOCATEHEAP             HASH("RtlReAllocateHeap")
#define LDRINITIALIZETHUNK            HASH("LdrInitializeThunk")
#define NTTESTALERT                   HASH("NtTestAlert")
#define RTLEXITUSERTHREAD             HASH("RtlExitUserThread")
#define TPRELEASECLEANUPGROUPMEMBERS  HASH("TpReleaseCleanupGroupMembers")
#define RTLUSERTHREADSTART            HASH("RtlUserThreadStart")
#define NTSETCONTEXTTHREAD            HASH("NtSetContextThread")
#define NTGETCONTEXTTHREAD            HASH("NtGetContextThread")
#define NTALERTRESUMETHREAD           HASH("NtAlertResumeThread")
#define NTSIGNALANDWAITFORSINGLEOBJECT HASH("NtSignalAndWaitForSingleObject")

// ========================================
// KERNEL32 API HASHES
// ========================================
#define WRITEFILE                     HASH("WriteFile")
#define CREATETHREAD                  HASH("CreateThread")
#define WAITFORSINGLEOBJECT           HASH("WaitForSingleObject")
#define CLOSEHANDLE                   HASH("CloseHandle")
#define GETEXITCODETHREAD             HASH("GetExitCodeThread")
#define CREATEFILEMAPPINGW            HASH("CreateFileMappingW")
#define MAPVIEWOFFILE                 HASH("MapViewOfFile")
#define INITIALIZECRITICALSECTION     HASH("InitializeCriticalSection")
#define ENTERCRITICALSECTION          HASH("EnterCriticalSection")
#define LEAVECRITICALSECTION          HASH("LeaveCriticalSection")
#define DELETECRITICALSECTION         HASH("DeleteCriticalSection")
#define FREELIBRARY                   HASH("FreeLibrary")
#define SETEVENT                      HASH("SetEvent")
#define HEAPCREATE                    HASH("HeapCreate")
#define HEAPDESTROY                   HASH("HeapDestroy")
#define QUERYPERFORMANCECOUNTER       HASH("QueryPerformanceCounter")
#define GETSYSTEMTIMEASFILETIME       HASH("GetSystemTimeAsFileTime")
#define GETCURRENTTHREADID            HASH("GetCurrentThreadId")
#define SLEEP                         HASH("Sleep")
#define CREATEEVENTA                  HASH("CreateEventA")
#define RESETEVENT                    HASH("ResetEvent")
#define QUEUEUSERAPC                  HASH("QueueUserAPC")
#define OPENTHREAD                    HASH("OpenThread")
#define GETTHREADCONTEXT              HASH("GetThreadContext")
#define GETMODULEHANDLEA              HASH("GetModuleHandleA")
#define LOADLIBRARYA                  HASH("LoadLibraryA")
#define VIRTUALPROTECT                HASH("VirtualProtect")
#define GETPROCESSHEAP                HASH("GetProcessHeap")
#define HEAPALLOC                     HASH("HeapAlloc")
#define HEAPFREE                      HASH("HeapFree")
#define HEAPREALLOC                   HASH("HeapReAlloc")
#define EXITTHREAD                    HASH("ExitThread")
#define CREATENAMEDPIPEA              HASH("CreateNamedPipeA")
#define CONNECTNAMEDPIPE              HASH("ConnectNamedPipe")
#define EXPANDENVIRONMENTSTRINGSA     HASH("ExpandEnvironmentStringsA")
#define REGOPENKEYEXA                 HASH("RegOpenKeyExA")
#define REGQUERYVALUEEXA              HASH("RegQueryValueExA")
#define REGCREATEKEYEXA               HASH("RegCreateKeyExA")
#define REGSETVALUEEXA                HASH("RegSetValueExA")
#define REGCLOSEKEY                   HASH("RegCloseKey")
#define DISCONNECTNAMEDPIPE           HASH("DisconnectNamedPipe")
#define READFILE                      HASH("ReadFile")
#define CREATEFILEA                   HASH("CreateFileA")
#define GETFILESIZE                   HASH("GetFileSize")
#define SETFILEPOINTER                HASH("SetFilePointer")
#define GETOVERLAPPEDRESULT           HASH("GetOverlappedResult")
#define GETLASTERROR                  HASH("GetLastError")
#define FLUSHFILEBUFFERS               HASH("FlushFileBuffers")

// ========================================
// ADVAPI32 API HASHES
// ========================================
#define SYSTEMFUNCTION033             HASH("SystemFunction033")

// ========================================
// USER32 API HASHES
// ========================================
#define POSTTHREADMESSAGEA            HASH("PostThreadMessageA")
#define GETMESSAGEA                   HASH("GetMessageA")
#define MESSAGEBOXA                   HASH("MessageBoxA")

// ========================================
// WINHTTP API HASHES
// ========================================
#define WINHTTPOPEN                   HASH("WinHttpOpen")
#define WINHTTPCONNECT                HASH("WinHttpConnect")
#define WINHTTPOPENREQUEST            HASH("WinHttpOpenRequest")
#define WINHTTPSENDREQUEST            HASH("WinHttpSendRequest")
#define WINHTTPRECEIVERESPONSE        HASH("WinHttpReceiveResponse")
#define WINHTTPQUERYHEADERS           HASH("WinHttpQueryHeaders")
#define WINHTTPREADDATA               HASH("WinHttpReadData")
#define WINHTTPCLOSEHANDLE            HASH("WinHttpCloseHandle")
#define WINHTTPWRITEDATA              HASH("WinHttpWriteData")
#define WINHTTPQUERYDATAAVAILABLE     HASH("WinHttpQueryDataAvailable")

#endif

