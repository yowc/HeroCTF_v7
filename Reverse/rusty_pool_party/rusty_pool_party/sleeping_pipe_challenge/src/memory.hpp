#ifndef _MEMORY_H
#define _MEMORY_H

#include "config_type.hpp"

#define MAX_BUFFER_SIZE_OOM 1024 * 1024 * 10 
// 10Mo buffer

void *alloc_mem(config_t *config, size_t size);

void *re_alloc_mem(config_t *config, void *ptr, size_t new_size);

BOOL dealloc_mem(config_t *config, void *ptr);

#endif
