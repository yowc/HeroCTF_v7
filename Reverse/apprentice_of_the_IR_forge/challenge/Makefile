CC = clang

SRC = src/
BIN = bin/

VALID_PASS = valid_pass
LLVM_PASS = apprentice_of_the_IR_forge
LLVM_EMIT = emit

LPASS = $(SRC)$(LLVM_PASS).cpp
LIB = $(BIN)$(LLVM_PASS).so

VPASS = $(SRC)$(VALID_PASS).c
OUT = $(BIN)$(VALID_PASS)

EMIT = $(BIN)$(LLVM_EMIT).ll

$(LIB): $(LPASS)
	$(CC) -shared -o $@ $< -fPIC

$(EMIT): $(VPASS)
	$(CC) -O1 -emit-llvm -S $< -o $@
	
$(OUT): $(LIB)
	$(CC) -O1 -fpass-plugin=$< $(VPASS) -o $@

init:
	@echo "Building" $(LLVM_PASS)
	@echo ---------------------------------
	mkdir -p bin

all: init $(LIB) $(OUT) $(EMIT)

clean:
	rm $(LIB) $(OUT) $(EMIT)
