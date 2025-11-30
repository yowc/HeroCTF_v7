// start.S
    .section .text.start
    .global _start
_start:
    ldr sp, =0x48000000

    bl main

1:  b 1b  