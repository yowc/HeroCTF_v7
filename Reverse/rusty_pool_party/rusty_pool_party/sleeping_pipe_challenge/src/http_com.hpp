#ifndef _HTTP_COM_H
#define _HTTP_COM_H

#include <windows.h>
#include <winnt.h>
#include <winhttp.h>
#include <stdint.h>
#include "utils.hpp"
#include "config_type.hpp"
#include "obfuscated_string.hpp"

typedef HINTERNET (WINAPI* fnWinHttpOpen)(
  const wchar_t *agent_w,
  uint32_t access_type,
  const wchar_t *proxy_w,
  const wchar_t *proxy_bypass_w,
  uint32_t flags
);

typedef HINTERNET (WINAPI* fnWinHttpConnect)(
  HINTERNET session,
  const wchar_t *server_name,
  INTERNET_PORT server_port,
  uint32_t reserved
);

typedef HINTERNET (WINAPI* fnWinHttpOpenRequest)(
  HINTERNET connect,
  const wchar_t *verb,
  const wchar_t *object_name,
  const wchar_t *version,
  const wchar_t *referrer,
  const wchar_t **accept_types,
  uint32_t flags
);

typedef BOOL (WINAPI* fnWinHttpSendRequest)(
  HINTERNET request,
  const wchar_t *headers,
  uint32_t headers_length,
  void *optional,
  uint32_t optional_length,
  uint32_t total_length,
  uint32_t *context
);

typedef BOOL (WINAPI* fnWinHttpReceiveResponse)(
  HINTERNET request,
  void *reserved
);

typedef BOOL (WINAPI* fnWinHttpQueryDataAvailable)(
  HINTERNET request,
  uint32_t *number_of_bytes_available
);

typedef BOOL (WINAPI* fnWinHttpReadData)(
  HINTERNET request,
  void *buffer,
  uint32_t number_of_bytes_to_read,
  uint32_t *number_of_bytes_read
);

typedef BOOL (WINAPI* fnWinHttpCloseHandle)(
  HINTERNET internet
);

int http_com(int is_get, config_t *config, uint8_t *to_send, size_t to_send_size, uint8_t **to_receive, size_t *to_receive_size);

#endif


