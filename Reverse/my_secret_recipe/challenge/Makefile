CC = gcc

SRC = src/
BIN = bin/

MSR = my_secret_recipe

MSR_SRC = $(SRC)$(MSR).c
TARGET = $(BIN)$(MSR)

$(TARGET): $(MSR_SRC)
	$(CC) $< -o $@

init:
	@echo "Building my_secret_recipe"
	@echo ---------------------------------
	mkdir -p bin

all: init $(TARGET)

clean:
	rm $(TARGET)
