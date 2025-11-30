from pwn import *

# context.log_level = "DEBUG"

AND = lambda x, y: [a & b for a, b in zip(x, y)]
IOR = lambda x, y: [a | b for a, b in zip(x, y)]

# io = remote("crypto.heroctf.fr", 9000)
io = process(["python3", "chall.py"])

flag_a = bytes.fromhex(io.recvlineS().strip("a = "))
flag_o = bytes.fromhex(io.recvlineS().strip("o = "))
io.sendlineafter(b"> ", b"\n")

flag = bytes(flag_a + flag_o)
old = None

while flag != old:
    old = flag
    a = bytes.fromhex(io.recvlineS().strip("a = "))
    o = bytes.fromhex(io.recvlineS().strip("o = "))
    io.sendlineafter(b"> ", b"\n")

    flag_a = IOR(flag_a, a)
    flag_o = AND(flag_o, o)

    flag = bytes(flag_a + flag_o)
    print(flag)
