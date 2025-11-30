CC = clang
OPT = opt

SRC = src/
BIN = bin/

VALID_PASS = valid_pass
LLVM_PASS = the_obsidian_optimizer
LLVM_EMIT = emit

LPASS = $(SRC)$(LLVM_PASS).cpp
LLVM_BIN = $(BIN)$(LLVM_PASS)

VPASS = $(SRC)$(VALID_PASS).c
OUT = $(BIN)$(VALID_PASS)

EMIT = $(BIN)$(LLVM_EMIT).ll
VEMIT = $(BIN)$(VALID_PASS).ll


$(EMIT): $(VPASS)
	$(CC) -O0 -emit-llvm -S $< -o $@

# TODO modify this ? useless 
$(OUT): $(EMIT)
	clang++ -Wall -Wextra -std=c++20 $(LPASS) -o $(LLVM_BIN) -lseccomp `llvm-config --cxxflags --ldflags --system-libs --libs core orcjit support native passes`

init:
	@echo "Building" $(LLVM_PASS)  
	@echo ---------------------------------
	mkdir -p bin
	
all: init $(OUT) $(EMIT)

clean:
	rm $(OUT) $(EMIT)
