// uart.h
#ifndef UART_H
#define UART_H

#include <stdint.h>

#define UART0_BASE   0x09000000UL 

void uart_putc(char c);
void uart_puts(const char *s);

#endif
