#ifndef _OBFUSCATED_STRING_HPP
#define _OBFUSCATED_STRING_HPP

#include <stdint.h>

// 16-byte compile-time XOR key - use constexpr function to avoid .rodata
constexpr uint8_t get_xor_key(size_t idx) {
    constexpr uint8_t key[16] = {
        0xAA, 0xCC, 0xB2, 0x12, 0x14, 0x12, 0x51, 0x7F,
        0x3E, 0x9A, 0x45, 0xD7, 0x88, 0x1B, 0xF3, 0x26
    };
    return key[idx % 16];
}

// Compile-time XOR encryption with rotating key
constexpr char xor_char(char c, size_t idx) {
    return c ^ get_xor_key(idx);
}

// String length calculation at compile-time
constexpr size_t const_str_len(const char* str) {
    return (*str == '\0') ? 0 : 1 + const_str_len(str + 1);
}

// Obfuscated string class - stores encrypted string inline in code
template<size_t N>
class ObfuscatedString {
private:
    char encrypted[N];
    char decrypted[N];

public:
    // Constructor encrypts at compile-time
    constexpr ObfuscatedString(const char (&str)[N]) : encrypted{}, decrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = xor_char(str[i], i);
        }
    }

    // Decrypt on-demand at runtime
    const char* decrypt() {
        for (size_t i = 0; i < N; i++) {
            decrypted[i] = xor_char(encrypted[i], i);
        }
        return decrypted;
    }

    // Get size
    constexpr size_t size() const {
        return N;
    }
};

// Helper macro to create obfuscated strings
#define OBFSTR(str) (ObfuscatedString<sizeof(str)>(str).decrypt())

// Alternative: Stack-based obfuscated string that doesn't use class storage
template<size_t N>
class StackObfuscatedString {
private:
    char encrypted[N];

public:
    constexpr StackObfuscatedString(const char (&str)[N]) : encrypted{} {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = xor_char(str[i], i);
        }
    }

    // Decrypt to a provided buffer
    void decrypt_to(char* buffer) const {
        for (size_t i = 0; i < N; i++) {
            buffer[i] = xor_char(encrypted[i], i);
        }
    }

    constexpr size_t size() const {
        return N;
    }
};

// Macro for stack-based strings (safer for shellcode)
#define OBFSTR_STACK(str) []() -> const char* { \
    constexpr StackObfuscatedString<sizeof(str)> obf(str); \
    static char buf[sizeof(str)]; \
    obf.decrypt_to(buf); \
    return buf; \
}()

// Compile-time XOR encryption for individual characters
constexpr char xor_encrypt_byte(char c, size_t idx) {
    return c ^ get_xor_key(idx);
}

// Helper to decrypt at runtime - inline the key directly
inline void xor_decrypt(char* buffer, size_t len) {
    const uint8_t key[16] = {
        0xAA, 0xCC, 0xB2, 0x12, 0x14, 0x12, 0x51, 0x7F,
        0x3E, 0x9A, 0x45, 0xD7, 0x88, 0x1B, 0xF3, 0x26
    };
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key[i % 16];
    }
}

// Template-based compile-time string encryption
template<size_t... Indices>
struct IndexSequence {};

template<size_t N, size_t... Indices>
struct MakeIndexSequence : MakeIndexSequence<N - 1, N - 1, Indices...> {};

template<size_t... Indices>
struct MakeIndexSequence<0, Indices...> {
    using type = IndexSequence<Indices...>;
};

// Encrypted string holder
template<size_t N>
struct EncryptedString {
    char data[N];

    template<size_t... Indices>
    consteval EncryptedString(const char(&str)[N], IndexSequence<Indices...>)
        : data{xor_encrypt_byte(str[Indices], Indices)...} {}

    consteval EncryptedString(const char(&str)[N])
        : EncryptedString(str, typename MakeIndexSequence<N>::type{}) {}

    // Decrypt to stack buffer at runtime
    void decrypt_to(char* out) const {
        const uint8_t key[16] = {
            0xAA, 0xCC, 0xB2, 0x12, 0x14, 0x12, 0x51, 0x7F,
            0x3E, 0x9A, 0x45, 0xD7, 0x88, 0x1B, 0xF3, 0x26
        };
        for (size_t i = 0; i < N; i++) {
            out[i] = data[i] ^ key[i % 16];
        }
    }
};

// Macro to create encrypted string on stack and decrypt it
#define XOR_STR(str, varname) \
    constexpr EncryptedString<sizeof(str)> _enc_##varname(str); \
    char varname[sizeof(str)]; \
    _enc_##varname.decrypt_to(varname)

// Wide string version - converts char* to wchar_t*
#define XOR_WSTR(str, varname) \
    constexpr EncryptedString<sizeof(str)> _enc_##varname(str); \
    char _tmp_##varname[sizeof(str)]; \
    _enc_##varname.decrypt_to(_tmp_##varname); \
    wchar_t varname[sizeof(str)]; \
    for (size_t _i_##varname = 0; _i_##varname < sizeof(str); _i_##varname++) { \
        varname[_i_##varname] = (wchar_t)_tmp_##varname[_i_##varname]; \
    }

#endif // _OBFUSCATED_STRING_HPP
