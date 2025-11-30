# Perilous

### Category

Crypto

### Difficulty

Very Easy

### Author

Alol

### Description

I've made a RC4 encryption service and I want you to test its security.
Decryption isn't supported though :p

TCP: `nc crypto.heroctf.fr 9001`

### Files

- [perilous.zip](perilous.zip)

### Write Up

The challenge is a remote service offering two options: RC4-encrypting the flag and RC4-encrypting a user-submitted message, both with a user-submitted key.

At first glance, this doesn't seem like much of a challenge. We known the key used to encrypt the flag, and RC4 is a symmetric cipher so why can't we just decrypt the flag without using the remote service? Because a mask is used during the encryption, first xored with the plaintext and then xored with the ciphertext, making them both effectively random to the end user and making offline decryption impossible (without knownledge of the mask).
We can't perform offline decryption but the remote service offers encryption, which with RC4 is synonymous with decryption, can't we "encrypt" our encrypted flag a second time to decrypt it? Even though it's the only way to invert the application of the mask, this is made impossible by because the challenge keeps a list of all previously used keys and forbids their use a second time.

The problem we face is thus the following: can we, through successive encryption using distinct keys, recover our flag?

It turns out we can, by taking advantage of the fact that, during the key scheduling phase, each index of the key is taken modulo the key's length. This means that keys with repeating patterns (such as `"AA"`, `"AAAA"`, `"AAAAAAAAAA"`, etc.) will result in the same SBox and keystream being generated. The [following paper](https://eprint.iacr.org/2013/241.pdf) details this issue further.

```py
class RC4:
    def __init__(self, key: bytes) -> None:
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            #                    ^--+------------^
            #                        \
            #        "A" == "AA" == "AAAA" == ... == "A" * 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
```
An other solution (which doesn't work in this case) would be to send two keys of length greater than 256 and identical to both their 256th byte. As we can see in the code above, the KSA iterates only on the first 256 key bytes. This solution doesn't work with the cryptography library as only certain key sizes are permitted (64, 128, 160, 192, 256, 40, 80 and 56 bits). 

Here's the full solve script to recover the flag.

```py
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

"""
Possible key sizes [64, 128, 160, 192, 256, 40, 80, 56]
[+] Starting local process '/usr/bin/python3': pid 2973294
Got enc_flag b'8aae9452bb94a592e5db5a2ed59c00744723cdc027d9364d5d5ac7cb6f90cbf25a53f345c802\n'
b'Hero{7h3_p3r1l5_0f_r3p3471n6_p4773rn5}'
[*] Stopped process '/usr/bin/python3' (pid 2973294)
"""
```

### Flag

Hero{7h3_p3r1l5_0f_r3p3471n6_p4773rn5}