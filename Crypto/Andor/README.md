# Andor

### Category

Crypto

### Difficulty

Easy

### Author

Alol

### Description

Would you rather be inside solving challenges AND getting flags OR outside touching grass ?

TCP: `nc crypto.heroctf.fr 9000`

### Files

- [andor.zip](andor.zip)

### Write Up

At each loop iteration we're given the result of half the flag AND-ed with a secret key and the other half OR-ed with another secret key. Since AND/ORs are applied on a per-bit basis, lets use a single flag bit `f` and single key bit `k` to illustrate. `a` and `o` denote the result of `f & k` and `f | k` respectively. 

| f | k | a (f & k) | o (f | k) |
| - | - | --------- | --------- |
| 0 | 0 |     0     |     0     |
| 0 | 1 |     0     |     1     |
| 1 | 0 |     0     |     1     |
| 1 | 1 |     1     |     1     |

As we can see from the truth table above, we only know with absolute certainty the value of `f` given `a` and `o` in two cases, when `a == 1` and when `o == 0`. To reformulate, each `a` will contain 0s (true and false positives) and sometimes 1s (always true positives) and each `o` will contain 1s (true and false positives) and sometimes 0s (always true positives).
We can query the server multiple times, OR the `a`s together (discards the fp 0s) and AND the `o`s together (discards the fp 1s) to recover each bit of the flag. 

```py
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
"""
[+] Starting local process '/usr/bin/python3': pid 3221221
b'@e\x12o\x12q0t\x1d4j`J%l23P] rE9 dJ\x14"`O{0nf\xf3\xb3_7q\xf5|l\x7f\xdfg\xfd<w\x7f4\xeed_x\xba\xf5n?5\x7f'
b'He\x12oRq0u\x1d4j`K%l33p_ r_y tZ4j`Ok0ff\xb3\xb3_7q\xf5|l?\xdfg\xfd4w\x7f4\xeed_x:\xb5n?5}'
b'Hero{y0u]4jd[5l33p_ r_y0u_4jd_c0ff3\xb3_3q\xf5tl?\xdffm4w_4\xeed_p21n75}'
b'Hero{y0u]4nd_5l33p_0r_y0u_4nd_c0ff33_3qutl=\xdffl4w_4nd_p01n75}'
b'Hero{y0u]4nd_5l33p_0r_y0u_4nd_c0ff33_3qutl=_fl4w_4nd_p01n75}'
b'Hero{y0u]4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4w_4nd_p01n75}'
b'Hero{y0u_4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4g_4nd_p01n75}'
b'Hero{y0u_4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4g_4nd_p01n75}'
[*] Stopped process '/usr/bin/python3' (pid 3221221)
"""
```

### Flag

Hero{y0u_4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4g_4nd_p01n75}