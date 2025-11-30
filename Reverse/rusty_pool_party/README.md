# Rusty Pool Party

### Category

Reverse

### Difficulty

Medium

### Author

Teddysbears

### Description

We hacked into EVIL_SPYWARE_MAKING_COMPANY (very very evil btw) we extracted some payloads from their server. We sent you one of them, could you help us understand what it does? 

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/) to download the binary.

Please make sure that the binary you run is issued from a running instance, else it will not be able to contact the C2. The downloaded binary is tied with the running instance. 

> The challenge takes 1-2 minutes to deploy.

### Write Up

TODO add reverse parts

1) The binary is a loader that uses indirect syscalls with VEH obfuscation/anti-debugging techniques, employing pool party (thread pool abuse) injection.
2) Find the moment where the injection is performed, before the memcpy operation.
3) Cross-reference the payload.
4) Find the RC4 key and encrypted shellcode.
5) Extract and decrypt it.
6) Find the flag as follows: 
Shellcode 1:
```c
int sub_0() {
  strcpy(v25, "FLAG PART_0: Hero{y0u_700_");
  v2 = sub_3B0(a1, a2, 0x5F3030375F7530LL, 2749822659LL);
  v3 = v2;
  if ( v2 )
  ...
}
```
Shellcode 2:
```c
int sub_0() {
  strcpy(v71, "FLAG PART_1: YoU_l1K3_7h4");
  v2 = v73;
  ...
}
```
Shellcode 3:
```c
int sub_0() {
  v2 = alloca(nullsub_1());
  strcpy(v113, "FLAG PART_2: t_KiNd_0F_P0");
  v3 = v115;
  ...
}
```
Shellcode 4: 
```c
int sub_0() {
  strcpy(v99, "FLAG PART_3: oL_P4r7Y}");
  v0 = v102;
  ...
}
```

### Flag

Hero{y0u_700_YoU_l1K3_7h4t_KiNd_0F_P0oL_P4r7Y}