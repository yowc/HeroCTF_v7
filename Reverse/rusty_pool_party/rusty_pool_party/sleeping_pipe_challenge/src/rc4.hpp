#ifndef _RC4_HPP
#define _RC4_HPP

#include <stdint.h>

// Simple RC4 implementation for command decryption
// Key is embedded in the command payload sent by C2

class RC4 {
private:
    uint8_t S[256];
    uint8_t i, j;

public:
    // Initialize RC4 state with key
    void init(const uint8_t* key, size_t key_len) {
        // KSA (Key Scheduling Algorithm)
        for (int idx = 0; idx < 256; idx++) {
            S[idx] = idx;
        }

        j = 0;
        for (int idx = 0; idx < 256; idx++) {
            j = (j + S[idx] + key[idx % key_len]) & 0xFF;
            // Swap S[i] and S[j]
            uint8_t temp = S[idx];
            S[idx] = S[j];
            S[j] = temp;
        }

        i = 0;
        j = 0;
    }

    // Encrypt/decrypt data in-place (RC4 is symmetric)
    void crypt(uint8_t* data, size_t len) {
        for (size_t idx = 0; idx < len; idx++) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;

            // Swap S[i] and S[j]
            uint8_t temp = S[i];
            S[i] = S[j];
            S[j] = temp;

            // XOR data with keystream
            uint8_t K = S[(S[i] + S[j]) & 0xFF];
            data[idx] ^= K;
        }
    }
};

// Helper function for one-shot RC4 encryption/decryption
inline void rc4_crypt(const uint8_t* key, size_t key_len, uint8_t* data, size_t data_len) {
    RC4 cipher;
    cipher.init(key, key_len);
    cipher.crypt(data, data_len);
}

#endif // _RC4_HPP
