from cryptography.hazmat.decrepit.ciphers import algorithms
from pwn import *

# context.log_level = "DEBUG"

key_sizes = [*algorithms.ARC4.key_sizes]
print("Possible key sizes", key_sizes)

# io = remote("crypto.heroctf.fr", 9000)
io = process(["python3", "chall.py"])

io.sendlineafter(b"flag k: ", b"41" * (key_sizes[0] // 8))
enc_flag = io.recvline()
print("Got enc_flag", enc_flag)

io.sendlineafter(b"k: ", b"41" * (key_sizes[1] // 8))
io.sendlineafter(b"m: ", enc_flag)
flag = io.recvlineS()

print(bytes.fromhex(flag))
