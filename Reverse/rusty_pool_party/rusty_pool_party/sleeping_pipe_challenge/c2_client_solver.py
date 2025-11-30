#!/usr/bin/env python3
"""
CTF Challenge Solver - Simulates shellcode communication with C2 server
This script replays the exact protocol the shellcodes use to communicate
"""

import requests
import struct
import sys
import os

# Command codes (must match pipe_protocol.hpp)
CMD_CHECK_FILE = 0x00
CMD_CHECK_REG = 0x01
CMD_WRITE_FILE = 0x02
CMD_WRITE_REG = 0x03
CMD_QUIT = 0xFF

# RC4 implementation (same as C2 server)
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


def get_command_name(cmd_code):
    """Get human-readable command name"""
    names = {
        CMD_CHECK_FILE: "CHECK_FILE",
        CMD_CHECK_REG: "CHECK_REG",
        CMD_WRITE_FILE: "WRITE_FILE",
        CMD_WRITE_REG: "WRITE_REG",
        CMD_QUIT: "QUIT"
    }
    return names.get(cmd_code, f"UNKNOWN(0x{cmd_code:02X})")


def parse_command(decrypted):
    """Parse decrypted command and return details"""
    if len(decrypted) < 1:
        return None, None

    cmd_code = decrypted[0]
    cmd_name = get_command_name(cmd_code)
    details = {}

    if cmd_code == CMD_CHECK_FILE:
        # Format: [cmd_code][null-terminated path]
        path = decrypted[1:].split(b'\x00')[0].decode('utf-8', errors='replace')
        details['path'] = path

    elif cmd_code == CMD_CHECK_REG:
        # Format: [cmd_code][null-terminated key][null-terminated value]
        parts = decrypted[1:].split(b'\x00')
        details['key'] = parts[0].decode('utf-8', errors='replace') if len(parts) > 0 else ""
        details['value'] = parts[1].decode('utf-8', errors='replace') if len(parts) > 1 else ""

    elif cmd_code == CMD_WRITE_FILE:
        # Format: [cmd_code][null-terminated path][data]
        null_idx = decrypted[1:].find(b'\x00')
        if null_idx != -1:
            details['path'] = decrypted[1:1+null_idx].decode('utf-8', errors='replace')
            details['data'] = decrypted[2+null_idx:].decode('utf-8', errors='replace')

    elif cmd_code == CMD_WRITE_REG:
        # Format: [cmd_code][null-terminated key][null-terminated value][data]
        parts = decrypted[1:].split(b'\x00', 2)
        details['key'] = parts[0].decode('utf-8', errors='replace') if len(parts) > 0 else ""
        details['value'] = parts[1].decode('utf-8', errors='replace') if len(parts) > 1 else ""
        details['data'] = parts[2].decode('utf-8', errors='replace') if len(parts) > 2 else ""

    elif cmd_code == CMD_QUIT:
        details['message'] = "Server requested quit"

    return cmd_name, details


def build_response(cmd_code, decrypted):
    """
    Build the proper response based on command type.
    The C2 server validates echo-back of paths/keys to ensure proper RC4 decryption.
    """
    if cmd_code == CMD_CHECK_FILE:
        # Response format: [path\0][file_content]
        # Echo the path from the command, add fake file content
        path = decrypted[1:].split(b'\x00')[0]
        fake_content = b"fake_file_content_for_validation"
        return path + b'\x00' + fake_content

    elif cmd_code == CMD_CHECK_REG:
        # Response format: [key_path\0][value_name\0][value_data]
        # Echo key and value from command, add fake registry data
        parts = decrypted[1:].split(b'\x00')
        key_path = parts[0] if len(parts) > 0 else b""
        value_name = parts[1] if len(parts) > 1 else b""
        fake_value = b"fake_registry_value_for_validation"
        return key_path + b'\x00' + value_name + b'\x00' + fake_value

    elif cmd_code == CMD_WRITE_FILE:
        # Response: just "SUCCESS"
        return b"SUCCESS"

    elif cmd_code == CMD_WRITE_REG:
        # Response: just "SUCCESS"
        return b"SUCCESS"

    else:
        return b"OK"


def do_command_cycle(base_url, stage):
    """
    Perform one command cycle:
    1. GET /command - receive encrypted command
    2. Decrypt and display
    3. Build proper echo-back response
    4. POST /response - send encrypted response
    """
    print(f"\n{'='*60}")
    print(f"  STAGE {stage}")
    print(f"{'='*60}")

    # Step 1: GET /command
    print(f"\n[>] GET {base_url}/command")
    try:
        resp = requests.get(f"{base_url}/command", timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None, None

    if resp.status_code != 200:
        print(f"[!] Server returned status {resp.status_code}")
        return None, None

    payload = resp.content
    print(f"[<] Received {len(payload)} bytes")

    # Step 2: Parse payload - Format: [1 byte key_len][key][encrypted_data]
    if len(payload) < 2:
        print("[!] Payload too small")
        return None, None

    key_len = payload[0]
    if len(payload) < 1 + key_len:
        print(f"[!] Invalid key length: {key_len}")
        return None, None

    rc4_key = payload[1:1+key_len]
    encrypted_data = payload[1+key_len:]

    print(f"\n[*] RC4 Key ({key_len} bytes): {rc4_key.hex()}")
    print(f"[*] Encrypted data ({len(encrypted_data)} bytes): {encrypted_data.hex()}")

    # Step 3: Decrypt
    decrypted = rc4_crypt(rc4_key, encrypted_data)
    print(f"\n[*] Decrypted data ({len(decrypted)} bytes):")
    print(f"    Hex: {decrypted.hex()}")
    print(f"    Raw: {decrypted}")

    # Step 4: Parse command
    cmd_name, details = parse_command(decrypted)
    print(f"\n[*] Command: {cmd_name}")
    if details:
        for k, v in details.items():
            print(f"    {k}: {v}")

    # Check for QUIT
    if decrypted[0] == CMD_QUIT:
        print("\n[!] Received QUIT command - stopping")
        return cmd_name, details

    # Step 5: Build proper echo-back response based on command type
    response_data = build_response(decrypted[0], decrypted)

    # Encrypt response with the same RC4 key
    encrypted_response = rc4_crypt(rc4_key, response_data)

    print(f"\n[>] POST {base_url}/response")
    print(f"    Response data: {response_data}")
    print(f"    Encrypted: {encrypted_response.hex()}")

    try:
        resp = requests.post(f"{base_url}/response", data=encrypted_response, timeout=10)
        print(f"[<] Server responded with status {resp.status_code}")
        if resp.content:
            print(f"    Body: {resp.content}")
    except requests.exceptions.RequestException as e:
        print(f"[!] POST failed: {e}")

    return cmd_name, details


def main():
    # Get C2 server address from environment or use default
    c2_ip = os.environ.get('C2_IP', '127.0.0.1')
    c2_port = os.environ.get('C2_PORT', '8080')

    base_url = f"http://{c2_ip}:{c2_port}"

    print("""
╔═══════════════════════════════════════════════════════════╗
║        CTF Challenge Solver - C2 Protocol Replay          ║
╠═══════════════════════════════════════════════════════════╣
║  This script simulates the shellcode communication        ║
║  to extract flag parts from the C2 server                 ║
╚═══════════════════════════════════════════════════════════╝
""")
    print(f"[*] Target C2 server: {base_url}")
    print(f"[*] (Set C2_IP and C2_PORT env vars to change)")

    flag_parts = []

    # Run through all stages
    for stage in range(5):  # Stages 0-4
        cmd_name, details = do_command_cycle(base_url, stage)  # Response built automatically

        if cmd_name is None:
            print("\n[!] Communication failed, stopping")
            break

        if cmd_name == "QUIT":
            break

        # Collect flag parts from WRITE commands
        if cmd_name == "WRITE_FILE" and details and 'data' in details:
            flag_parts.append(details['data'])
            print(f"\n[+] Captured flag part: {details['data']}")

        if cmd_name == "WRITE_REG" and details and 'data' in details:
            flag_parts.append(details['data'])
            print(f"\n[+] Captured flag part: {details['data']}")

    # Print final results
    print(f"\n{'='*60}")
    print("  FINAL RESULTS")
    print(f"{'='*60}")

    if flag_parts:
        full_flag = ''.join(flag_parts)
        print(f"\n[+] Flag parts collected:")
        for i, part in enumerate(flag_parts):
            print(f"    Part {i+1}: {part}")
        print(f"\n[+] Complete flag: {full_flag}")
    else:
        print("\n[!] No flag parts collected")
        print("[!] Make sure the C2 server has flag.txt with the flag content")


if __name__ == "__main__":
    main()
