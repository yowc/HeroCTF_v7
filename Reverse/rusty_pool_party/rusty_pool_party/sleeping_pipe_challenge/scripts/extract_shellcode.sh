#!/bin/bash
# Extract shellcode starting from the entry point

if [ $# -ne 2 ]; then
    echo "Usage: $0 <input.exe> <output.bin>"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

# Get entry point address
ENTRY=$(x86_64-w64-mingw32-objdump -f "$INPUT" | grep "start address" | awk '{print $3}')

# Get .text section start address
TEXT_START=$(x86_64-w64-mingw32-objdump -h "$INPUT" | grep "\.text" | awk '{print "0x"$4}')

# Calculate offset of entry point within .text section
OFFSET=$((ENTRY - TEXT_START))

echo "[+] Entry point: $ENTRY"
echo "[+] .text start: $TEXT_START"
echo "[+] Offset: $OFFSET (0x$(printf '%x' $OFFSET))"

# Extract .text section first
x86_64-w64-mingw32-objcopy -O binary -j .text "$INPUT" "$OUTPUT.tmp"

# Skip to entry point offset and extract the rest
dd if="$OUTPUT.tmp" of="$OUTPUT" bs=1 skip=$OFFSET 2>/dev/null

# Cleanup
rm -f "$OUTPUT.tmp"

echo "[+] Shellcode extracted to $OUTPUT"
wc -c "$OUTPUT"
