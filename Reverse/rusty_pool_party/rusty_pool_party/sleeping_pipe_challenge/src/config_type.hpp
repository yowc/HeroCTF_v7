#ifndef _CONFIG_TYPE_H
#define _CONFIG_TYPE_H

#include <stdint.h>
#include <windows.h>

// CARE we do not count kernel32.dll 
#define MODULE_NUMBER 6

#define MAX_SERVER_SIZE 256  // Support long DNS names
#define MAX_PORT_SIZE 5
#define MAX_ENDPOINT_SIZE 128
#define MAX_AGENT_SIZE 40
#define MAX_BINARY_NAME_SIZE 128
#define MAX_SLEEP_TIMER_SIZE 4

typedef HANDLE (WINAPI* fnGetProcessHeap)();
typedef void *(WINAPI* fnHeapAlloc)(
  HANDLE heap,
  uint32_t flags,
  size_t bytes
);
typedef BOOL (WINAPI* fnHeapFree)(
  HANDLE heap,
  uint32_t flags,
  void *mem
);
typedef void *(WINAPI* fnHeapReAlloc)(
  HANDLE heap,
  uint32_t flags,
  void *mem,
  size_t bytes
);

typedef void (WINAPI *fnSleep)(
  uint32_t milli_seconds
);

typedef HMODULE (WINAPI* fnGetModuleHandleA)(
  char *module_name
);

typedef HMODULE (WINAPI* fnLoadLibraryA)(
  char *lib_file_name
);

typedef struct config_s {
  wchar_t *server;
  wchar_t *endpoint;
  wchar_t *agent;
  char *binary_name;
  uint32_t sleep_timer;
  uint16_t port;

  HMODULE ntdll;
  HMODULE kernel32;
  HMODULE user32;
  HMODULE winhttp;
  HMODULE advapi32;
  HMODULE shell32;
  HMODULE gdi32;
  HMODULE winmm;

  fnGetProcessHeap fn_get_process_heap;
  fnHeapAlloc fn_heap_alloc;
  fnHeapFree fn_heap_free;
  fnHeapReAlloc fn_heap_re_alloc;
} config_t;


#endif
