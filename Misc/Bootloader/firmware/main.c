#include <stdint.h>
#include <stddef.h>
#include "uart.h"
#include "aes.h"

#define FLAG_LEN 39
#define FLAG_XOR_KEY 0x23

static const uint8_t flag_obf[FLAG_LEN] = {
    0x6b, 0x46, 0x51, 0x4c, 0x58,
    0x70, 0x76, 0x60, 0x60, 0x10,
    0x70, 0x70, 0x65, 0x76, 0x6f,
    0x6f, 0x7a, 0x7c, 0x10, 0x7b,
    0x73, 0x6f, 0x13, 0x12, 0x14,
    0x10, 0x67, 0x7c, 0x61, 0x13,
    0x13, 0x77, 0x6f, 0x13, 0x17,
    0x67, 0x10, 0x71, 0x5e
};

static const uint8_t aes_key[16]  = {
    0x13, 0x37, 0xC0, 0xDE,
    0xBA, 0xAD, 0xF0, 0x0D,
    0x42, 0x42, 0x42, 0x42,
    0x99, 0x88, 0x77, 0x66
};

static void hex_byte(uint8_t b, char out[2])
{
    const char *hex = "0123456789ABCDEF";
    out[0] = hex[(b >> 4) & 0xF];
    out[1] = hex[b & 0xF];
}

static void decode_flag(uint8_t *dst)
{
    for (size_t i = 0; i < FLAG_LEN; i++) {
        dst[i] = flag_obf[i] ^ FLAG_XOR_KEY;
    }
}

int main(void)
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key);

    uint8_t buffer[48] = {0};

    decode_flag(buffer);  

    for (size_t i = 0; i < sizeof(buffer); i += 16) {
        AES_ECB_encrypt(&ctx, buffer + i);
    }

    uart_puts("Boot completed, here is your flag : ");

    char out[2];
    for (size_t i = 0; i < sizeof(buffer); i++) {
        hex_byte(buffer[i], out);
        uart_putc(out[0]);
        uart_putc(out[1]);
    }

    uart_puts("\n");

    while (1) {
        // idle
    }

    return 0;
}
