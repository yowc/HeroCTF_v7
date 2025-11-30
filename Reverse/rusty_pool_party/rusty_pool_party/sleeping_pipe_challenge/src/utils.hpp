#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <windows.h>
#include <stdint.h>
// gcc -o utils utils.c -D VERBOSE=4

#if VERBOSE >= 1
#define BUILD_HOUR ((__TIME__[0] - '0') * 10 + __TIME__[1] - '0')
#define BUILD_MIN ((__TIME__[3] - '0') * 10 + __TIME__[4] - '0')
#define BUILD_SEC ((__TIME__[6] - '0') * 10 + __TIME__[7] - '0')

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#ifndef LOG_FILENAME 
#define LOG_FILENAME NULL
#endif

#ifndef LOG_FILE
#define LOG_FILE 0
#endif

#ifndef LOG_TIME 
#define LOG_TIME 0
#endif

#ifndef VERBOSE 
#define VERBOSE 0
#endif 


// Log goes to terminal
void log_vprintf(const char *fmt, ...);

// Log goes to a file if LOG_FILENAME is defined
void log_file(const char *fmt, ...);

#define PRINT_FUNCTION(FMT, ...)             \
        do {                                 \
          if(LOG_FILE && LOG_FILENAME) {     \
            log_file(FMT, ##__VA_ARGS__);    \
          } else {                           \
            log_vprintf(FMT, ##__VA_ARGS__); \
          }                                  \
        } while(0);                          \
    
#define __LOG(FMT, ...)                            \
          do {                                     \
            if (LOG_TIME) {                        \
              time_t timing = time(NULL);          \
              struct tm* ltm = localtime(&timing); \
              PRINT_FUNCTION(ANSI_COLOR_BLUE "[%02d:%02d:%02d] " ANSI_COLOR_RESET FMT, ltm->tm_hour, ltm->tm_min, ltm->tm_sec, ##__VA_ARGS__) \
            }                                      \
            else{                                  \
              PRINT_FUNCTION(FMT, ##__VA_ARGS__)   \
            }                                      \
          }while(0);                               \

#define LOG(FMT,...)                                            \
          do {                                                  \
            __LOG(FMT, ##__VA_ARGS__);                          \
          } while(0);                                           \

#define INFO(FMT, ...) LOG(ANSI_COLOR_CYAN "[i] " ANSI_COLOR_RESET FMT "\n", ##__VA_ARGS__)
#define INFO_SUCCESS(FMT, ...) LOG(ANSI_COLOR_GREEN "[+] " ANSI_COLOR_RESET FMT "\n", ##__VA_ARGS__)
#else
#define INFO(FMT, ...) do {} while (0)
#define INFO_SUCCESS(FMT, ...) do {} while (0)
#endif
#if VERBOSE >= 2
#define WARN(FMT, ...) LOG(ANSI_COLOR_MAGENTA "[!] " ANSI_COLOR_RESET FMT "\n", ##__VA_ARGS__)
#else
#define WARN(FMT, ...) do {} while (0)
#endif
#if VERBOSE >= 3
#define DEBUG(FMT, ...) LOG(ANSI_COLOR_YELLOW "[d] " ANSI_COLOR_RESET FMT "\n", ##__VA_ARGS__)
#else
#define DEBUG(FMT, ...) do {} while (0)
#endif 
#if VERBOSE >= 4
#define ERROR_LOG(FMT, ...) LOG(ANSI_COLOR_RED "[-] " ANSI_COLOR_RESET FMT " from %s:%d:%s()\n", ##__VA_ARGS__,__FILE__, __LINE__, __func__)
#else
#define ERROR_LOG(FMT, ...) do {} while (0)
#endif

// Maybe add something like if heapalloc result 0 then goto failed and print not enough memory ? 
#define ALLOC_MEM(SIZE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SIZE)
#define DEALLOC_MEM(PTR) HeapFree(GetProcessHeap(), 0, PTR)
#define RE_ALLOC_MEM(PTR, NEW_SIZE) HeapReAlloc(GetProcessHeap(), 0, PTR, NEW_SIZE)

#define XOR_KEY "\xAA\xCC\xB2\x12\x14\x12\x51\x7F"
void xor_decrypt(char *str, const char *xored_str, size_t len); 


size_t _strlen(const char *str);
size_t _wstrlen(const wchar_t *wstr);
uint32_t _strtoul(const char *str);
char *_strcat(char *dest, char *src);
int _memcpy_s(void *dest, size_t destsz, void *src, size_t count);
int _strncat_s(char *dest, size_t dest_size, char *src, size_t count);
char *__itoa(int value, char *str, int base);
void *_memset_0(uint8_t *dest, size_t count);
int _memcmp(void *ptr1, void *ptr2, size_t size);

// Safe thread exit macro for debug vs release mode
// In debug mode (VERBOSE >= 1), use return instead of ExitThread to avoid crashes
// In injected shellcode, we can't call ExitThread() - it will crash the host process
// Instead, use WaitForSingleObject on an event that will never be signaled (infinite wait, 0 CPU)
#if VERBOSE >= 1
#define SAFE_EXIT_THREAD(code) return (code)
#else
#define SAFE_EXIT_THREAD(code) do { \
    typedef HANDLE (WINAPI* fnCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, const char*); \
    typedef DWORD (WINAPI* fnWaitForSingleObject)(HANDLE, DWORD); \
    HMODULE k32 = get_module_handle(HASH_KERNEL32); \
    if (k32) { \
        fnCreateEventA fn_create_event = (fnCreateEventA)get_proc_address(k32, CREATEEVENTA); \
        fnWaitForSingleObject fn_wait = (fnWaitForSingleObject)get_proc_address(k32, WAITFORSINGLEOBJECT); \
        if (fn_create_event && fn_wait) { \
            HANDLE never_signaled = fn_create_event(NULL, TRUE, FALSE, NULL); \
            if (never_signaled) fn_wait(never_signaled, 0xFFFFFFFF); \
        } \
    } \
    while(1) { __asm__ volatile("pause"); } \
    __builtin_unreachable(); \
} while(0)
#endif

#endif
