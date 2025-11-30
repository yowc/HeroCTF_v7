SECTIONS
{
    .text :
    {
        *(.text$A)
        *(.text$B)
        *(.text$C)
        *(.text)
        *(.text*)
    }

    .data :
    {
        *(.data)
        *(.data*)
    }

    /DISCARD/ :
    {
        *(.drectve)
        *(.debug*)
        *(.pdata)
        *(.xdata)
        *(.edata)
        *(.idata)
        *(.CRT*)
        *(.tls*)
        *(.eh_frame)
        *(.rdata*)
        *(.data*)
    }
}
