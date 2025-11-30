# Story Contest

### Category

Pwn

### Difficulty

Easy

### Author

25kGoldn

### Description

It’s time for you to tell your best story, and maybe you’ll be rewarded accordingly. Good luck !

Deploy an instance at https://deploy.heroctf.fr/.

### Files

- [storycontest.zip](storycontest.zip)

### Write Up

The vulnerability is in this function:
```c
__int64 __fastcall submit_story(unsigned int fd)
{
  char s[64];      // [rbp-E0h]
  _BYTE buf[136];  // [rbp-A0h]
  ssize_t n;
  int len;

  send_line(fd, "=== Submit a new story ===");
  send_line(fd, "The jury needs a short moment to prepare the evaluation...");
  send_str(fd, "Choose a length limit for your story: ");

  len = recv_int(fd);
  if ( len <= 0 )
    return send_line(fd, "Invalid length.");

  g_story_len = len;       // global

  if ( len > 128 )
    return send_line(fd, "Right now, we cannot process stories that long.");

  send_line(fd, "[*] The jury is thinking (0.5s)...");
  usleep(0x7A120u);        // 0.5s

  send_line(fd, "Now type your story:");

  n = read(fd, buf, g_story_len);   // <-- uses global g_story_len
  ...
}

```

The key bug is that the user-supplied length is checked (len > 128) using the local variable len but the read() uses the global g_story_len, which can be changed by another thread in between.
buf is only 136 bytes, but if another connection sets g_story_len = 256 during the sleep, then read(fd, buf, 256) overflows the stack and overwrites the saved return address.

Now there is two way:

1. Jump into bonus entry here with a ropchain to set bonus_enabled:
   ```
    .text:0000000000401612                 mov     cs:bonus_enabled, 1
    .text:000000000040161C                 nop
    .text:000000000040161D                 pop     rbp
    .text:000000000040161E                 retn
   ```
   and call gift to make thread exit. A new thread can now show the results and read the flag.

2. With a ropchain call gift and leak the libc to get a pop rdi and make a second payload to set bonus_entry and show_results. (Example of this: [exploit.py](exploit.py))

### Flag

Hero{971e70feb761e8daf0abcb7eb7376bff2}
