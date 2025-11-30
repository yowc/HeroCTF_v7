#include "utils.hpp"

#if VERBOSE >= 1

void log_vprintf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

// Log goes to a file if LOG_FILENAME is defined
void log_file(const char *fmt, ...)
{
    FILE *log_fd = fopen(LOG_FILENAME,"a+");
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(log_fd, fmt, argptr);
    va_end(argptr);
    fclose(log_fd);
} 
#endif

size_t _strlen(const char *str) {
  // WARN THIS IS OPTIMIZE AS STRLEN ...
  // size_t result = 0;
  // while(*(string++)){
  //   result++;
  // }
  // SAME 
  // while (*string) {
  //   result++;
  //   string++;
  //   }
    const char *p = str;
    while (*p) ++p;

    return (size_t)(p - str);
}

size_t _wstrlen(const wchar_t *wstr) {
    size_t len = 0;
    while (wstr && wstr[len] != L'\0') {
        len++;
    }
    return len;
}

uint32_t _strtoul(const char *str) {
  uint32_t result = 0;

  while (*str) {
      char c = *str++;
      if (c >= '0' && c <= '9') {
          result = result * 10 + (c - '0');
      } else {
          break;
      }
  }

  return result;
}

char *_strcat(char *dest, char *src) {
    char *original = dest;

    while (*dest) {
        dest++;
    }
    while (*src) {
        *dest++ = *src++;
    }

    *dest = '\0'; 
    return original;
}

int _strncat_s(char *dest, size_t destsz, char *src, size_t count) {
    size_t i = 0;

    if (!dest || !src || destsz == 0) {
        return 1; // EINVAL
    }
    while (i < destsz && dest[i] != '\0') {
        i++;
    }
    if (i == destsz) {
        return 1;
    }
    size_t j = 0;
    while (j < count && i + j < destsz - 1 && src[j] != '\0') {
        dest[i + j] = src[j];
        j++;
    }
    dest[i + j] = '\0';
    if (j < count && src[j] != '\0') {
        return 1; 
    }

    return 0; 
}

int _memcpy_s(void *dest, size_t destsz, void *src, size_t count) {

    if (!dest || !src) {
        return 1;
    }
    if (count > destsz) {
        return 1; 
    }
    
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < count; i++) {
        d[i] = s[i];
    }

    return 0; 
}

char *__itoa(int value, char *str, int base) {
    if (base < 2 || base > 36) {
        *str = '\0';
        return str;
    }

    char *ptr = str, *ptr1 = str, tmp;
    int n = (value < 0 && base == 10) ? -value : value;
    int is_negative = (value < 0 && base == 10);

    do {
        int rem = n % base;
        *ptr++ = (rem < 10) ? rem + '0' : rem - 10 + 'a';
        n /= base;
    } while (n);

    if (is_negative) {
        *ptr++ = '-';
    }

    *ptr = '\0';
    ptr--;
    while (ptr1 < ptr) {
        tmp = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp;
    }

    return str;
}

void *_memset_0(uint8_t *dest, size_t count) {
    unsigned char *p = (unsigned char *)dest;
    while (count--) {
        *p++ = (unsigned char)0;
    }
    return dest;
}

int _memcmp(void *ptr1, void *ptr2, size_t size) {
    unsigned char *p1 = (unsigned char *)ptr1;
    unsigned char *p2 = (unsigned char *)ptr2;

    for (size_t i = 0; i < size; i++) {
        if (p1[i] != p2[i]) {
            return (int)p1[i] - (int)p2[i];
        }
    }

    return 0;
}

void xor_decrypt(char *str, const char *xored_str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] = xored_str[i] ^ XOR_KEY[i % (sizeof(XOR_KEY) - 1)];
    }
}


