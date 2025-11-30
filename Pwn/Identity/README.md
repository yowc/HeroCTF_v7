# Identity

### Category

Pwn

### Difficulty

Medium

### Author

25kGoldn

### Description

I added a protection layer in front of my database, it’s safe now… right? Right??

Deploy an instance at https://deploy.heroctf.fr/.

### Files

- [identity.zip](identity.zip)

### Write Up

## Getting the leak:

The leak resides in this function :
```c
void __cdecl fill_status_detail(SecResp *resp, uint32_t status)
{
  char buf[136];
  char *msg;

  resp->status = status;
  if ( status )
  {
    if ( status == 2 )
    {
      msg = strerror_r(110, buf, 0x80u);
      if ( g_last_status == 2 )
      {
        resp->detail = g_last_detail;
      }
      else
      {
        resp->detail = 2;
        g_last_status = 2;
        g_last_detail = (uint64_t)msg;
      }
    }
    else if ( status == g_last_status )
    {
      resp->detail = g_last_detail;
    }
    ...
  }
}

```
The TCC path in securityd leaks a libc pointer because fill_status_detail caches a pointer to a stack buffer and later reuses it, and identityd prints it back to the client. On first TCC timeout, fill_status_detail saves in **g_last_detail** the msg pointer returned by strerror_r, which actually points to the local buffer buf. On the second TCC timeout, resp->detail is directly filled with this old pointer and the pointer is leak to the user via identityd.

## Out of bound:
The core bug is in how securityd indexes the TCC session array inside a global struct that also contains the handler function pointers.

In this function:
```c
TccSession *__cdecl tcc_session_create(uint32_t target_id, uint32_t target_uid, uint32_t caller_uid)
{
  int idx; 
  TccSession *s;

  idx = g_next_session_idx++;
  if ( idx > 8 )                // Max tcc sessions == 8
    idx = 8;

  s = &g_state.sessions[idx];   // <-- out-of-bounds when idx == 8

  s->target_id  = target_id;
  s->target_uid = target_uid;
  s->caller_uid = caller_uid;

  memcpy(s->role, g_last_role, 0x100u);  // 256 bytes from g_last_role

  pthread_mutex_init(&s->mtx, 0);
  pthread_cond_init(&s->cv, 0);

  return s;
}

```
Because MAX_TCC_SESSIONS is 8 and the array is declared as sessions[8], valid indices are 0–7, but when g_next_session_idx reaches 8, idx is set to 8 and &g_state.sessions[8] actually points just past the end of the sessions array, into the next field which is the handlers array.

From there, TccSession initialization writes target_id, target_uid, caller_uid, the 256-byte role buffer (fully controlled via g_last_role), the done and result flags, and the mutex/condvar initialization data into that out-of-bounds region, corrupting the handler function pointers.

Once you’ve triggered the out-of-bounds write, you can overwrite the handlers and later invoke them. By calling the corresponding handler and using it as a stack pivot into the role data (which lives on the stack), you can then execute an arbitrary ROP chain.

## Exploitation

Exploitation isn’t completely straightforward because a seccomp filter blocks execve and dup, and direct access to the flag in identity.db is gated by the TCC checks. However, since the database file is still readable/writable, you can open identity.db, seek to the fixed offset of the entry with id 1337, overwrite its UID to bypass the security checks, and then simply issue GET 1337 again to retrieve the flag.
Here is an example: [exploit.py](exploit.py)

### Flag

Hero{3d7595fe172ef52a99fdc60d}
