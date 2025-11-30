// The one that should only wake up the master
// This shellcode sleeps for 5 seconds then sends wakeup signal to master pipe

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "memory.hpp"
#include "obfuscated_string.hpp"
#include "pipe_protocol.hpp"

// Shellcode entry point - placed at start of .text section
// Accepts optional parameter for thread creation compatibility
extern "C" __attribute__((section(".text$A"))) DWORD shellcode_main(LPVOID lpParameter) {
    // Ignore parameter for now
    (void)lpParameter;
    DEBUG("=== Alarm Shellcode Starting ===");

    // Flag part 0 hidden in shellcode (stack string)
    volatile char flag_part_0[] = {'F','L','A','G',' ','P','A','R','T','_','0',':',' ','H','e','r','o','{','y','0','u','_','7','0','0','_','\0'};
    if (flag_part_0[0] == 'X') return 0;  // Never true, but prevents optimization

    // Resolve required modules
    HMODULE kernel32 = get_module_handle(HASH_KERNEL32);
    if (!kernel32) {
        ERROR_LOG("Failed to get kernel32 handle");
        return 1;
    }

    // Get required functions
    typedef void (WINAPI* fnSleep)(uint32_t milliseconds);
    typedef void (WINAPI* fnExitThread)(uint32_t exit_code);
    typedef HANDLE (WINAPI* fnCreateFileA)(const char*, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES, uint32_t, uint32_t, HANDLE);
    typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);

    fnSleep fn_sleep = (fnSleep)get_proc_address(kernel32, SLEEP);
    fnExitThread fn_exit_thread = (fnExitThread)get_proc_address(kernel32, EXITTHREAD);
    fnCreateFileA fn_create_file_a = (fnCreateFileA)get_proc_address(kernel32, CREATEFILEA);
    fnWriteFile fn_write_file = (fnWriteFile)get_proc_address(kernel32, WRITEFILE);
    fnCloseHandle fn_close_handle = (fnCloseHandle)get_proc_address(kernel32, CLOSEHANDLE);

    if (!fn_sleep || !fn_exit_thread || !fn_create_file_a || !fn_write_file || !fn_close_handle) {
        ERROR_LOG("Failed to resolve required functions");
        return 1;
    }

    // Sleep for 5 seconds (alarm delay)
    DEBUG("Sleeping for 5 seconds...");
    fn_sleep(5000);
    DEBUG("Waking up!");

    // Connect to master pipe and send wakeup signal
    XOR_STR("\\\\.\\pipe\\master", pipe_name);
    DEBUG("Connecting to master pipe: %s", pipe_name);

    HANDLE pipe = fn_create_file_a(
        pipe_name,
        0x40000000 | 0x80000000,  // GENERIC_READ | GENERIC_WRITE
        0,                          // No sharing
        NULL,
        3,                          // OPEN_EXISTING
        0,
        NULL
    );

    if (pipe == (HANDLE)-1) {  // INVALID_HANDLE_VALUE
        ERROR_LOG("Failed to connect to master pipe");
        return 1;
    }

    // Send wakeup message
    DEBUG("Sending wakeup signal to master...");
    pipe_msg_header_t header;
    header.type = PIPE_MSG_WAKEUP;
    header.size = 0;

    uint32_t written = 0;
    fn_write_file(pipe, &header, sizeof(header), &written, NULL);

    if (written == sizeof(header)) {
        INFO_SUCCESS("Wakeup signal sent successfully!");
    } else {
        ERROR_LOG("Failed to send wakeup signal");
    }

    // Cleanup and exit
    fn_close_handle(pipe);
    SAFE_EXIT_THREAD(0);
}

#if VERBOSE >= 1
// Wrapper for debug mode
int main() {
    shellcode_main(NULL);
    return 0;
}
#endif
