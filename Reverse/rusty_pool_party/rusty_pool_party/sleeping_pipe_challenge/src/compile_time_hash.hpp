#ifndef _COMPILE_TIME_HASH_HPP
#define _COMPILE_TIME_HASH_HPP

#include <stdint.h>

// FNV-1a 32-bit hash constants
#define FNV_32_PRIME ((uint32_t)0x01000193)
#define FNV_32_OFFSET_BASIS ((uint32_t)0x811c9dc5)

// Compile-time consteval FNV-1a hash implementation (forces compile-time evaluation)
consteval uint32_t fnv1a_32_recursive(const char* str, uint32_t hash = FNV_32_OFFSET_BASIS) {
    return (*str == '\0') ? hash : fnv1a_32_recursive(str + 1, (hash ^ static_cast<uint32_t>(*str)) * FNV_32_PRIME);
}

// Compile-time consteval for wide char strings (UTF-16 to UTF-8 lowercase conversion + hash)
consteval uint32_t fnv1a_32_wchar_recursive(const wchar_t* wstr, uint32_t hash, size_t index) {
    if (wstr[index] == L'\0') {
        return hash;
    }

    // Convert to lowercase (basic ASCII only)
    char current_chr = static_cast<char>(wstr[index] & 0xFF);
    if (current_chr > 64 && current_chr < 91) {
        current_chr += 32;
    }

    uint32_t new_hash = (hash ^ static_cast<uint32_t>(static_cast<uint8_t>(current_chr))) * FNV_32_PRIME;
    return fnv1a_32_wchar_recursive(wstr, new_hash, index + 1);
}

consteval uint32_t fnv1a_32_wchar(const wchar_t* wstr) {
    return fnv1a_32_wchar_recursive(wstr, FNV_32_OFFSET_BASIS, 0);
}

// Main macro for compile-time hashing of string literals
#define HASH(str) (fnv1a_32_recursive(str))

// Macro for compile-time hashing of wide string literals (for DLL names)
#define HASH_W(wstr) (fnv1a_32_wchar(wstr))

// Helper to compute string length at compile time
consteval size_t const_strlen(const char* str) {
    return (*str == '\0') ? 0 : 1 + const_strlen(str + 1);
}

consteval size_t const_wstrlen(const wchar_t* wstr) {
    return (*wstr == L'\0') ? 0 : 1 + const_wstrlen(wstr + 1);
}

// Verify hash at compile time (useful for testing)
template<uint32_t expected, uint32_t actual>
struct hash_verify {
    static_assert(expected == actual, "Hash mismatch!");
    static constexpr bool value = true;
};

#endif // _COMPILE_TIME_HASH_HPP
