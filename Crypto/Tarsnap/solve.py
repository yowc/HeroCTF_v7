import string

from pwn import cyclic, remote, process
from tqdm import tqdm

non_repeat_data = bytearray(cyclic(length=31481, alphabet=range(128, 256), n=3))

# io = remote("crypto.heroctf.fr", 9001)
io = process(["python3", "chall.py"])


def run(content) -> bytes:
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Filename: ", b"")
    io.sendlineafter(b"Content: ", content.hex().encode())
    io.sendlineafter(b"> ", b"3")
    return bytes.fromhex(io.recvlineS().split()[2])


CHARSET = string.digits + string.ascii_lowercase + string.ascii_uppercase + "_" + "}"
flag = b"Hero{"

while not flag.endswith(b"}"):
    d = {}

    for c in tqdm(CHARSET, leave=False):
        l1 = len(run(non_repeat_data + flag + c.encode() + b"#"))
        d[c] = l1

    flag += min(d, key=d.get).encode()
    print(f"{flag=}")
