#!/usr/bin/env python3
"""
CTF Challenge C2 Server - Stateful Protocol with RC4
Sends commands, waits for responses, validates data, reuses RC4 keys
"""

import http.server
import socketserver
import struct
import os
import sys
import threading

# Command codes (must match pipe_protocol.hpp)
CMD_CHECK_FILE = 0x00
CMD_CHECK_REG = 0x01
CMD_WRITE_FILE = 0x02
CMD_WRITE_REG = 0x03
CMD_QUIT = 0xFF

# RC4 implementation
def rc4_crypt(key, data):
    """Simple RC4 encryption/decryption"""
    S = list(range(256))
    j = 0

    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)

    return bytes(result)

class CTFHandler(http.server.BaseHTTPRequestHandler):
    """Handle C2 requests - stateful protocol with response validation"""

    # Class variables to track state (protected by lock for thread safety)
    current_stage = 0  # Which command we're on
    current_rc4_key = None  # RC4 key for current command
    waiting_for_response = False  # Are we waiting for POST response?
    state_lock = threading.Lock()  # Lock to prevent race conditions

    # Flag parts loaded from flag.txt
    flag_part1 = None
    flag_part2 = None

    def do_GET(self):
        """Handle GET /command - send encrypted command"""
        if self.path != '/command':
            self.send_error(404)
            return

        # Acquire lock to safely check and update state
        with CTFHandler.state_lock:
            # Don't send next command if we're waiting for a response
            if CTFHandler.waiting_for_response:
                print(f"[!] Still waiting for POST response to stage {CTFHandler.current_stage}")
                self.send_error(429, "Too Many Requests - waiting for response")
                return

            # Generate new RC4 key for this command
            CTFHandler.current_rc4_key = os.urandom(16)
            rc4_key = CTFHandler.current_rc4_key
            current_stage = CTFHandler.current_stage  # Capture stage while locked

            # Mark that we're now waiting for response (do this while locked)
            CTFHandler.waiting_for_response = True

        # Build command based on current stage (using local copy)
        if current_stage == 0:
            # Stage 0: CHECK_FILE - Check if %appdata%/flag_1.txt exists with data
            print(f"\n[+] Stage 0: Sending CHECK_FILE command")
            print(f"    Target: %appdata%\\flag_1.txt")

            # Command format: [1 byte cmd_code][null-terminated path]
            path = b"%appdata%\\flag_1.txt\x00"
            command = struct.pack('B', CMD_CHECK_FILE) + path

        elif current_stage == 1:
            # Stage 1: CHECK_REG - Check if registry key exists
            print(f"\n[+] Stage 1: Sending CHECK_REG command")
            print(f"    Target: HKCU\\Software\\CTF\\flag_2")

            # Command format: [1 byte cmd_code][null-terminated key path][null-terminated value name]
            key_path = b"HKCU\\Software\\CTF\x00"
            value_name = b"flag_2\x00"
            command = struct.pack('B', CMD_CHECK_REG) + key_path + value_name

        elif current_stage == 2:
            # Stage 2: WRITE_FILE - Write first part of flag
            flag_part1 = CTFHandler.flag_part1
            print(f"\n[+] Stage 2: Sending WRITE_FILE command")
            print(f"    Target: %appdata%\\flag_1.txt")
            print(f"    Data: {flag_part1.decode()}")

            # Command format: [1 byte cmd_code][null-terminated path][data]
            path = b"%appdata%\\flag_1.txt\x00"
            command = struct.pack('B', CMD_WRITE_FILE) + path + flag_part1

        elif current_stage == 3:
            # Stage 3: WRITE_REG - Write second part of flag
            flag_part2 = CTFHandler.flag_part2
            print(f"\n[+] Stage 3: Sending WRITE_REG command")
            print(f"    Target: HKCU\\Software\\CTF\\flag_2")
            print(f"    Data: {flag_part2.decode()}")

            # Command format: [1 byte cmd_code][null-terminated key][null-terminated value][data]
            key_path = b"HKCU\\Software\\CTF\x00"
            value_name = b"flag_2\x00"
            command = struct.pack('B', CMD_WRITE_REG) + key_path + value_name + flag_part2

        else:
            # Final stage: QUIT
            if current_stage == 4:
                print(f"\n[!] All stages complete - Sending QUIT command")
            else:
                print(f"\n[!] Error detected - Sending QUIT command to terminate shellcode")
            command = struct.pack('B', CMD_QUIT)

        # Encrypt command with RC4
        encrypted = rc4_crypt(rc4_key, command)

        # Build response: [1 byte key_len][key][encrypted_data]
        payload = struct.pack('B', len(rc4_key)) + rc4_key + encrypted

        print(f"    RC4 Key: {rc4_key.hex()}")
        print(f"    Encrypted command: {encrypted.hex()[:40]}...")
        print(b"    Payload: " + payload)

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

        # If this was a QUIT command (stage >= 4), reset state for next connection
        if current_stage >= 4:
            with CTFHandler.state_lock:
                CTFHandler.waiting_for_response = False
                CTFHandler.current_stage = 0
                CTFHandler.current_rc4_key = None
                print(f"    [*] State reset to 0 - ready for next connection")
        # Note: waiting_for_response was already set to True in the lock above
        elif current_stage < 4:
            print(f"    [*] Waiting for POST /response...")

    def do_POST(self):
        """Handle POST /response - receive and validate response"""
        if self.path != '/response':
            self.send_error(404)
            return

        # Check waiting flag with lock
        with CTFHandler.state_lock:
            if not CTFHandler.waiting_for_response:
                print(f"[!] Received unexpected POST response")
                self.send_error(400, "Not waiting for response")
                return

            # Capture current state while locked
            current_rc4_key = CTFHandler.current_rc4_key
            current_stage = CTFHandler.current_stage

        # Read response data
        content_length = int(self.headers.get('Content-Length', 0))
        response_data = self.rfile.read(content_length)

        print(f"\n[<] Received POST /response ({len(response_data)} bytes)")

        # Decrypt response with same RC4 key
        response_body = b""  # Error message to send back
        next_stage = current_stage + 1  # Default: advance to next stage

        if current_rc4_key and len(response_data) > 0:
            decrypted = rc4_crypt(current_rc4_key, response_data)
            print(f"    Decrypted response: {decrypted[:100]}")

            # Validate response based on stage (using local copy)
            if current_stage == 0:
                # Stage 0: CHECK_FILE response
                # Expected format: [path\0][file_content]
                expected_path = b"%appdata%\\flag_1.txt\x00"
                if len(decrypted) == 0:
                    print(f"    [!] ERROR: File is EMPTY or not found!")
                    print(f"    [!] The file %appdata%\\flag_1.txt must exist and contain data")
                    print(f"    [!] Sending 'error file empty' back to client")
                    response_body = b"error file empty"
                    next_stage = 999
                elif not decrypted.startswith(expected_path):
                    print(f"    [!] ERROR: Response does not echo back the correct path!")
                    print(f"    [!] Expected path: {expected_path}")
                    print(f"    [!] Got: {decrypted[:50]}")
                    print(f"    [!] Client did not decrypt command correctly (wrong RC4 key?)")
                    response_body = b"error invalid response"
                    next_stage = 999
                else:
                    file_content = decrypted[len(expected_path):]
                    print(f"    [+] Path echo verified: %appdata%\\flag_1.txt")
                    print(f"    [+] File check passed - file has {len(file_content)} bytes")

            elif current_stage == 1:
                # Stage 1: CHECK_REG response
                # Expected format: [key_path\0][value_name\0][value_data]
                expected_key = b"HKCU\\Software\\CTF\x00"
                expected_value = b"flag_2\x00"
                expected_prefix = expected_key + expected_value
                if len(decrypted) == 0:
                    print(f"    [!] ERROR: Registry key is EMPTY or not found!")
                    print(f"    [!] HKCU\\Software\\CTF\\flag_2 must exist with data")
                    print(f"    [!] Sending 'error registry empty' back to client")
                    response_body = b"error registry empty"
                    next_stage = 999
                elif not decrypted.startswith(expected_prefix):
                    print(f"    [!] ERROR: Response does not echo back the correct key/value!")
                    print(f"    [!] Expected prefix: {expected_prefix}")
                    print(f"    [!] Got: {decrypted[:50]}")
                    print(f"    [!] Client did not decrypt command correctly (wrong RC4 key?)")
                    response_body = b"error invalid response"
                    next_stage = 999
                else:
                    value_data = decrypted[len(expected_prefix):]
                    print(f"    [+] Key/value echo verified: HKCU\\Software\\CTF\\flag_2")
                    print(f"    [+] Registry check passed - value has {len(value_data)} bytes")
                    print(f"    [+] Value: {value_data.decode('utf-8', errors='replace')}")

            elif current_stage == 2:
                # Stage 2: WRITE_FILE response (should be "SUCCESS" or error)
                status = decrypted.decode('utf-8', errors='replace')
                print(f"    [+] Write file status: {status}")

            elif current_stage == 3:
                # Stage 3: WRITE_REG response (should be "SUCCESS" or error)
                status = decrypted.decode('utf-8', errors='replace')
                print(f"    [+] Write registry status: {status}")
                print(f"\n    ========================================")
                print(f"    [!] FLAG PARTS WRITTEN!")
                print(f"    [!] Part 1: %appdata%\\flag_1.txt")
                print(f"    [!] Part 2: HKCU\\Software\\CTF\\flag_2")
                print(f"    [!] Assemble the flag: <part1><part2>")
                print(f"    ========================================\n")
        else:
            # Empty response or no RC4 key
            print(f"    [!] Empty response or no RC4 key available")

            # For CHECK_FILE and CHECK_REG stages, empty response means failure
            if current_stage == 0:
                print(f"    [!] ERROR: File is EMPTY or not found!")
                print(f"    [!] The file %appdata%\\flag_1.txt must exist and contain data")
                print(f"    [!] Sending 'error file empty' back to client")
                response_body = b"error file empty"
                next_stage = 999  # Jump to QUIT
            elif current_stage == 1:
                print(f"    [!] ERROR: Registry key is EMPTY or not found!")
                print(f"    [!] HKCU\\Software\\CTF\\flag_2 must exist with data")
                print(f"    [!] Sending 'error registry empty' back to client")
                response_body = b"error registry empty"
                next_stage = 999  # Jump to QUIT

        # Advance to next stage BEFORE sending HTTP response
        # Use lock to atomically update both flags - prevents race condition
        with CTFHandler.state_lock:
            CTFHandler.waiting_for_response = False
            CTFHandler.current_stage = next_stage
            print(f"    [*] Advancing to stage {CTFHandler.current_stage}")

        # Send HTTP response with optional error message in body
        self.send_response(200)
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        if response_body:
            self.wfile.write(response_body)

    def log_message(self, format, *args):
        """Custom logging"""
        # Suppress default HTTP logging to keep output clean
        pass

def run_server(host="0.0.0.0", port=8080):
    """Start the C2 server"""
    with socketserver.TCPServer((host, port), CTFHandler) as httpd:
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║           CTF Challenge C2 Server - v2                    ║
║           Stateful Protocol with Response Validation      ║
╠═══════════════════════════════════════════════════════════╣
║  Listening on: {host}:{port:<43}║
║                                                           ║
║  Protocol Flow:                                           ║
║  1. GET /command  → Send encrypted command                ║
║  2. Wait for POST /response with result                   ║
║  3. Decrypt & validate response                           ║
║  4. Repeat for next command                               ║
║                                                           ║
║  Stages:                                                  ║
║  0: CHECK_FILE  - Verify flag_1.txt exists               ║
║  1: CHECK_REG   - Verify registry key exists             ║
║  2: WRITE_FILE  - Write flag part 1                      ║
║  3: WRITE_REG   - Write flag part 2                      ║
║  4: QUIT        - Exit shellcode                         ║
╚═══════════════════════════════════════════════════════════╝
[*] Waiting for connections...
""")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")

if __name__ == "__main__":
    # Read C2 configuration from environment variables
    c2_ip = "0.0.0.0" # os.environ.get('C2_IP', '0.0.0.0')
    c2_port = 8080 # int(os.environ.get('C2_PORT', '8080'))

    print(f"[*] C2 Configuration:")
    print(f"    IP:   {c2_ip} (from C2_IP env var)")
    print(f"    Port: {c2_port} (from C2_PORT env var)")
    print(f"")

    # Load flag from flag.txt and split into two parts
    default_flag_part_1 = b"missing_flag_part_1_call_admin"
    default_flag_part_2 = b"missing_flag_part_2_call_admin"
    flag_file = os.path.join(os.path.dirname(__file__), 'flag.txt')
    try:
        with open(flag_file, 'r') as f:
            flag_content = f.read().strip()

        # Split flag into two parts (roughly equal)
        mid_point = len(flag_content) // 2
        CTFHandler.flag_part1 = flag_content[:mid_point].encode()
        CTFHandler.flag_part2 = flag_content[mid_point:].encode()

        print(f"[+] Flag loaded from {flag_file}")
        print(f"    Part 1 ({len(CTFHandler.flag_part1)} bytes): {CTFHandler.flag_part1.decode()}")
        print(f"    Part 2 ({len(CTFHandler.flag_part2)} bytes): {CTFHandler.flag_part2.decode()}")
        print(f"    Full flag: {flag_content}")
        print(f"")
    except FileNotFoundError:
        print(f"[!] Warning: {flag_file} not found - using default flag parts")
        CTFHandler.flag_part1 = default_flag_part_1
        CTFHandler.flag_part2 = default_flag_part_2
        print(f"")
    except Exception as e:
        print(f"[!] Error loading flag: {e}")
        CTFHandler.flag_part1 = default_flag_part_1
        CTFHandler.flag_part2 = default_flag_part_2
        print(f"")

    run_server(c2_ip, c2_port)
