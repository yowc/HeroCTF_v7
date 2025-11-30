#!/bin/bash

# Ensure all output goes to stdout/stderr properly
exec 2>&1

# Generate random suffix (redirect errors to suppress broken pipe warnings)
RANDOM_SUFFIX=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16 2>/dev/null)

# Define temporary file paths
VALID_PASS_FILE="/home/challenge/src/valid_pass_${RANDOM_SUFFIX}.c"
MAKEFILE_TEMP="/home/challenge/Makefile_${RANDOM_SUFFIX}"

# Cleanup function
cleanup() {
    rm -f "$VALID_PASS_FILE" 2>/dev/null
    rm -f "$MAKEFILE_TEMP" 2>/dev/null
    rm -f "$TEMP_OUTPUT" 2>/dev/null
    rm -f "/home/challenge/bin/valid_pass_${RANDOM_SUFFIX}" 2>/dev/null
    rm -f "/home/challenge/bin/emit_${RANDOM_SUFFIX}.ll" 2>/dev/null
}

# Ensure cleanup on exit
trap cleanup EXIT

# Read user input
echo "Enter your valid_pass.c code (end with EOF or Ctrl+D):"
cat > "$VALID_PASS_FILE"

# Check if input was provided
if [ ! -s "$VALID_PASS_FILE" ]; then
    echo "Error: No input provided"
    exit 1
fi

# Copy and modify Makefile
cp /home/challenge/Makefile "$MAKEFILE_TEMP"

# Replace VALID_PASS and LLVM_EMIT lines with the new random filenames
sed -i "s/^VALID_PASS = valid_pass$/VALID_PASS = valid_pass_${RANDOM_SUFFIX}/" "$MAKEFILE_TEMP"
sed -i "s/^LLVM_EMIT = emit$/LLVM_EMIT = emit_${RANDOM_SUFFIX}/" "$MAKEFILE_TEMP"

# Run make all with the modified Makefile
cd /home/challenge
make -f "$MAKEFILE_TEMP" all 2>&1

# Run the_obsidian_optimizer binary
echo ""
echo "Running the_obsidian_optimizer..."

# Check if binary exists and is executable
if [ ! -x /home/challenge/the_obsidian_optimizer ]; then
    echo "ERROR: Binary not found or not executable"
    exit 1
fi

# Capture output to a temporary file to ensure it's fully written
EMIT_FILE="/home/challenge/bin/emit_${RANDOM_SUFFIX}.ll"

# Check if emit file was created
if [ ! -f "$EMIT_FILE" ]; then
    echo "ERROR: Emit file not found: $EMIT_FILE"
    ls -la /home/challenge/bin/ 2>&1
    exit 1
fi

# Run the binary directly without redirection
echo "=== Binary Output Start ==="
/home/challenge/the_obsidian_optimizer "$EMIT_FILE"
EXIT_CODE=$?

echo "=== Binary Output End ==="

exit $EXIT_CODE
