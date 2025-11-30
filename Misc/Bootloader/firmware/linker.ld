/* linker.ld */
ENTRY(_start)

SECTIONS
{
  . = 0x40200000;

  .text : {
    *(.text.start)
    *(.text*)
  }

  .rodata : {
    *(.rodata*)
  }

  .data : {
    *(.data*)
  }

  .bss : {
    *(.bss*)
    *(COMMON)
  }
}
