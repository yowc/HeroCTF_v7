#include "memory.hpp"

void *alloc_mem(config_t *config, size_t size) {
  return  config->fn_heap_alloc(config->fn_get_process_heap(), HEAP_ZERO_MEMORY, size);
}

void *re_alloc_mem(config_t *config, void *ptr, size_t new_size) {
  return config->fn_heap_re_alloc(config->fn_get_process_heap(), 0, ptr, new_size);
}

BOOL dealloc_mem(config_t *config, void *ptr) {
  return config->fn_heap_free(config->fn_get_process_heap(), 0, ptr);
}
