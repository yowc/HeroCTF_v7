# Tarsnap

### Category

Crypto

### Difficulty

Medium

### Author

Alol

### Description

Why do encrypted ZIPs exist but not encrypted TARs ?
Anyway, I made a 100% super secure online backup service because I'm truely paranoid.

TCP: `nc crypto.heroctf.fr 9002`

### Files

- [tarsnap.zip](tarsnap.zip)

### Write Up

To recover the flag we're going to mount a [CRIME](https://en.wikipedia.org/wiki/CRIME)-style attack on the backup service.

CRIME TL;DR: By controlling part of a plaintext, we can leak data by bruteforcing bytes and watching the size of the compressed output. Better compression ratio => smaller output => our plaintext is present earlier in the data.

The plan seems simple: for each possible byte, create an archive, add the flag, add our own data + byte and check the size of the encrypted archive. Rinse and repeat for each character in the flag and done!
However, if we run this naive attack on the remote service it won't work. This is because of the TAR archive format, TAR files contain metadata and padding, which also gets compressed and make the compression ratio hard to predict. To make the attack stable, we're going to use the fact that [DEFLATE](https://en.wikipedia.org/wiki/Deflate) (the compression algorithm used by [gzip](https://en.wikipedia.org/wiki/Gzip)) uses [LZ77](https://en.wikipedia.org/wiki/LZ77_and_LZ78), which uses a 32kb sliding window.

We want to make sure that, when we perform the attack, only the flag and not the TAR data before it are in DEFLATE's sliding window. To do this we prepend our known plaintext + char to test with just enough uncompressable padding for the flag (and nothing before it) to be in the sliding window. The length of padding to use is determined beforehand using [infgen](https://github.com/madler/infgen/).

```bash
# ~ infgen -mc < tar_with_flag_and_31481_padding.tgz | less
#

literal 'Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_1n5734d}'
...
match 5 32505
copy 'Hero{'


```


```py
import string

from pwn import cyclic, remote, process
from tqdm import tqdm

non_repeat_data = bytearray(cyclic(length=31481, alphabet=range(128, 256), n=3))

# io = remote("alol.re", 8080)
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


"""
[+] Starting local process '/usr/bin/python3': pid 3267897
flag=b'Hero{5'                                                                                
flag=b'Hero{5h'                                                                               
flag=b'Hero{5h0'                                                                              
...
flag=b'Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_1n5734d'                                   
flag=b'Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_1n5734d}'                                  
[*] Stopped process '/usr/bin/python3' (pid 3267897)
"""
```
### Flag

Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_1n5734d}