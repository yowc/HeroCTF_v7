# The Chef's Secret Recipe

### Category

Reverse

### Difficulty

Very Easy

### Author

Teddysbears

### Description

You will never guess the secret recipe for my secret flag-cake !

### Files

- [my_secret_recipe](my_secret_recipe)

### Write Up

The challenge is a simple string compare between the user input and a dynamic constructed string. 
The binary is a x86_64 ELF, not stripped.
```sh
 file my_secret_recipe
bin/my_secret_recipe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6cb2bb5b0deb01af01607f6b8bec1664200e591d, for GNU/Linux 4.4.0, not stripped

 objdump -M intel --disassemble=main my_secret_recipe
```
```s
15fb:	48 8d 55 c0          	lea    rdx,[rbp-0x40]           <--- dynamic string
15ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
1603:	48 89 d6             	mov    rsi,rdx                  
1606:	48 89 c7             	mov    rdi,rax
1609:	e8 09 fe ff ff       	call   1417 <parse_recipe>
160e:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60] 
1612:	48 83 c0 08          	add    rax,0x8
1616:	48 8b 10             	mov    rdx,QWORD PTR [rax]      <--- user input string 
1619:	48 8d 45 c0          	lea    rax,[rbp-0x40]
161d:	48 89 d6             	mov    rsi,rdx
1620:	48 89 c7             	mov    rdi,rax
1623:	e8 48 fa ff ff       	call   1070 <strcmp@plt>        <--- string comparison
```
We will check the value of the dynamic string with ltrace. Debuger and breakpoint would do the trick too. 

```sh
 ltrace ./bin/my_secret_recipe aa
...
strcmp("sweetness", "sweetness")                                                      = 0
strtok(nil, " \n")                                                                    = nil
strcmp("Hero{0h_N0_y0u_60T_My_S3cReT_C4k"..., "aa")                                   = -25
...
```

We didn't get the full flag, but with ltrace option (-s for string max size) we get:  

```sh
 ltrace -s 500 my_secret_recipe aa
...
strcmp("sweetness", "sweetness")                                                      = 0
strtok(nil, " \n")                                                                    = nil
strcmp("Hero{0h_N0_y0u_60T_My_S3cReT_C4k3_R3c1pe}", "aa")                             = -25
...
```

### Flag

Hero{0h_N0_y0u_60T_My_S3cReT_C4k3_R3c1pe}
