CROSS_COMPILE ?= arm-none-eabi-
CC  = $(CROSS_COMPILE)gcc
LD  = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

CFLAGS = -Wall -O2 -ffreestanding -nostdlib -nostartfiles
LDFLAGS = -T linker.ld

OBJS = start.o main.o uart.o aes.o mini_libc.o

all: firmware.bin

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

firmware.elf: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

firmware.bin: firmware.elf
	$(OBJCOPY) -O binary \
		-R .note -R .note.* \
		-R .comment -R .comment.* \
		-R .ARM.attributes -R .ARM.attributes.* \
		$< $@

clean:
	rm -f *.o firmware.elf firmware.bin
