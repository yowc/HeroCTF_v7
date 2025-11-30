# Sleeping Pipe

### Category

Reverse

### Difficulty

Hard

### Author

Teddysbears

### Description

To solve this challenge you need to solve the previous challenge `Rusty Pool Party` this is the second part. 

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

> The challenges takes 1-2 minutes to deploy.

### Write Up

TODO: Add reverse engineering results (during CTF?)

1) Reverse all four shellcodes: alarm_shellcode wakes up the master shellcode, manage_com shellcode handles HTTP requests, and file_shellcode handles file and registry key access
2) Check the first HTTP communication:

Shellcode request:
```
GET /command HTTP/1.1
Connection: Keep-Alive
User-Agent: CTFAgent/1.0
Host: 127.0.0.1:8080
```

Server response:
```
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.12.6
Date: Fri, 21 Nov 2025 22:38:37 GMT
Content-Type: application/octet-stream
Content-Length: 39

....{....s..8..
L'..g.B ..0MS.....Z.9.x
```

3) Reverse the shellcode's protocol to extract the following format: `[key_len][rc4_key][encrypted_command]`
4) Decrypt the first command as: `b'\x00%appdata%\\flag_1.txt\x00'`
5) Reverse file_shellcode to check the result: `b'\x00%appdata%\\flag_1.txt\x00<FILE_CONTENT>'` encrypted with the same RC4 key
6) Send it to the server
7) Send another GET request
8) Decrypt the second shellcode request as before: `b'\x01HKCU\\Software\\CTF\x00flag_2\x00'`
9) The file shellcode checks the registry key and sends back the content as: `b'\x01HKCU\\Software\\CTF\x00flag_2\x00<REGISTRY_KEY_CONTENT>'` (encrypted)
10) Send it to the server
11) Send another GET request
12) Server sends: `b'\x02%appdata%\\flag_1.txt\x00Hero{N0w_d0_y0U_H34r_7h3_S'` (first flag part)
13) Send another GET request
14) Server sends: `b'\x03HKCU\\Software\\CTF\x00flag_2\x000unD_0f_7he_sl33pInG_pipEs}'` (second flag part)

The Python server to mimic the shellcode's actions can be found at [c2_client_server.py](challenge/c2_server.py).

### Flag

Hero{N0w_d0_y0U_H34r_7h3_S0unD_0f_7he_sl33pInG_pipEs}