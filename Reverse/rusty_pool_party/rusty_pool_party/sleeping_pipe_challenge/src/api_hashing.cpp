#include "api_hashing.hpp"

// Extended LDR_DATA_TABLE_ENTRY with undocumented fields
typedef struct _LDR_DATA_TABLE_ENTRY_EXT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... more fields we don't need
} LDR_DATA_TABLE_ENTRY_EXT, *PLDR_DATA_TABLE_ENTRY_EXT;

// Retrieve a pointer to the current process TEB we assume we always are in 64bits
PTEB get_teb() {
  PTEB teb;
  __asm__ (
    "mov %0, gs:[0x30]"
    : "=r" (teb)
  );
  DEBUG("TEB = %p", teb);
  return teb;
}

// Retrieve a pointer to the current process PEB
PPEB get_peb() {
  PTEB teb = get_teb();
  if (!teb) {
    ERROR_LOG("TEB is NULL!");
    return NULL;
  }
  PPEB peb = teb->ProcessEnvironmentBlock;
  DEBUG("PEB = %p", peb);
  return peb;
}

void utf16_to_utf8_lower_case(wchar_t *utf16_buffer, size_t utf16_buffer_len, uint8_t *utf8_buffer){
    char current_chr = 0;

    for(size_t i = 0; i < utf16_buffer_len; i++) {
     current_chr = ((char *)utf16_buffer)[i * 2];
     if((current_chr > 64) && (current_chr < 91)) {
       current_chr += 32;
     }
     utf8_buffer[i] = current_chr; 
    } 
}

uint32_t get_crc32(uint8_t *data, uint32_t data_size) {
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0;i < data_size;i++) {
		char ch = data[i];
		for (size_t j = 0;j < 8;j++) {
			uint32_t b = (ch ^ crc) & 1;
			crc >>= 1;
			if (b) crc = crc ^ 0xEDB88320;
			ch >>= 1;
		}
	}

	return ~crc;
}

hash_t get_fnv32a(uint8_t *data, uint32_t data_size) {
  uint8_t *bp = data;
  uint8_t *be = bp + data_size;
  hash_t hash = 0x811c9dc5;

  while (bp < be) {
    hash ^= (hash_t)*bp++;
    hash *= FNV_32_PRIME;
  }

  return hash;
}

// Get function address from it's name hash (calculated from HASH_IT function)
uint64_t get_proc_address(HMODULE module_handle, hash_t function_hash) {
  PIMAGE_DOS_HEADER dos_header = NULL;
  PIMAGE_NT_HEADERS64 nt_headers = NULL;
  IMAGE_OPTIONAL_HEADER64 optional_header;
  PIMAGE_EXPORT_DIRECTORY export_directory = NULL;
  uint64_t function_name_array = 0, function_pointer_array = 0, function_ordinal_name_array = 0;
  uint64_t function_address = 0;

  if(!module_handle) {
    DEBUG("module_handle is NULL, it's not supposed to");
    goto invalid_param;
  }

  dos_header = (PIMAGE_DOS_HEADER)module_handle;
  nt_headers = (PIMAGE_NT_HEADERS64) ((uint64_t)module_handle + dos_header->e_lfanew);
  if(nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    DEBUG("NT_HEADERS64 have wrong signature, abort");
    goto invalid_param;
  }

  optional_header = (IMAGE_OPTIONAL_HEADER64)nt_headers->OptionalHeader;
  export_directory = (PIMAGE_EXPORT_DIRECTORY)((uint64_t)module_handle + optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  function_name_array = (uint64_t)module_handle + export_directory->AddressOfNames;
  function_pointer_array = (uint64_t)module_handle + export_directory->AddressOfFunctions;
  function_ordinal_name_array = (uint64_t)module_handle + export_directory->AddressOfNameOrdinals;

  //DEBUG("Searching through %llu exported functions for hash 0x%x", export_directory->NumberOfFunctions, function_hash);
  for(uint64_t i = 0; i < export_directory->NumberOfFunctions; i++)  {
    uint8_t *function_name = (uint8_t*)((uint64_t)module_handle + *((uint32_t*)function_name_array));
    hash_t hash = HASH_IT(function_name, _strlen((char*)function_name));
    #if VERBOSE >= 4
    // Only show first 10 functions to avoid spam
    // if(i < 10) {
    //   DEBUG("  [%llu] %s (hash: 0x%x)", i, function_name, hash);
    // }
    #endif
    if(hash == function_hash) {
      //DEBUG("Found function: %s at index %llu", function_name, i);
      function_pointer_array += sizeof(uint32_t) * *((uint16_t*)function_ordinal_name_array);
      function_address = (uint64_t)module_handle + *((uint32_t*)function_pointer_array);
      //DEBUG("Function address: %p", (void*)function_address);
      break;
    }
    function_name_array += sizeof(uint32_t);
    function_ordinal_name_array += sizeof(uint16_t);
  }

invalid_param: 
  return function_address;
}

// Get module handle from it's name hash (calculated from HASH_IT function)
HMODULE get_module_handle(hash_t module_hash) {
  HMODULE module_handle = NULL;
  PPEB peb = NULL;
  PPEB_LDR_DATA ldr = NULL;
  PLDR_DATA_TABLE_ENTRY_EXT data_table_entry = NULL;
  size_t module_name_len = 0;
  hash_t hash;
  uint8_t utf8_buffer[UTF8_BUFFER_SIZE] = {0};

  DEBUG("Getting PEB...");
  peb = get_peb();
  if (!peb) {
    ERROR_LOG("PEB is NULL!");
    return NULL;
  }

  DEBUG("Getting Ldr...");
  ldr = peb->Ldr;
  if (!ldr) {
    ERROR_LOG("Ldr is NULL!");
    return NULL;
  }
  DEBUG("Ldr = %p", ldr);

  DEBUG("Getting first module entry...");
  PLIST_ENTRY list_entry = ldr->InMemoryOrderModuleList.Flink;
  DEBUG("First list entry = %p", list_entry);

  int count = 0;
  while(list_entry != &ldr->InMemoryOrderModuleList && count < 100) { // Limit to prevent infinite loop
    // CONTAINING_RECORD: subtract offset of InMemoryOrderLinks from list_entry
    // InMemoryOrderLinks is at offset 0x10 (16 bytes) in LDR_DATA_TABLE_ENTRY_EXT
    data_table_entry = (PLDR_DATA_TABLE_ENTRY_EXT)((uint8_t*)list_entry - offsetof(LDR_DATA_TABLE_ENTRY_EXT, InMemoryOrderLinks));
    DEBUG("Module entry %d at %p", count, data_table_entry);

    // Use BaseDllName instead of FullDllName to match just "kernel32.dll" not full path
    if (data_table_entry->BaseDllName.Buffer && data_table_entry->BaseDllName.Length > 0) {
      module_name_len = data_table_entry->BaseDllName.Length / 2;
      if (module_name_len > 0 && module_name_len < UTF8_BUFFER_SIZE) {
        utf16_to_utf8_lower_case(data_table_entry->BaseDllName.Buffer, module_name_len, utf8_buffer);
        hash = HASH_IT(utf8_buffer, module_name_len);
        DEBUG("Checking module: %s (hash: 0x%x, target: 0x%x)", utf8_buffer, hash, module_hash);
        if(hash == module_hash) {
          module_handle = (HMODULE)data_table_entry->DllBase;
          DEBUG("Found module! Handle: %p", module_handle);
          _memset_0(utf8_buffer, UTF8_BUFFER_SIZE);
          break;
        }
        _memset_0(utf8_buffer, UTF8_BUFFER_SIZE);
      }
    }
    list_entry = list_entry->Flink;
    count++;
  }

  DEBUG("Checked %d modules", count);
  return module_handle;
}
