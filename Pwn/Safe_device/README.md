# Safe Device

### Category

Pwn

### Difficulty

Hard

### Author

Itarow

### Description

I develop a secure driver with a secure recompiled kernel 😈 but I don't share all my secrets to make it harden ...

Credentials : `user:user`

Note : To transfer files on the virtual machine you may need to use `-O` option of `scp` binary. Get root in your local docker before spawn an instance.

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Files

- [./players/safe_device_players.zip](./players/safe_device_players.zip)

### Write Up

I will update the write-up with a cleaner one later. 
But these are the steps involved :
- The kernel module gives arbitrary read, it takes an address as an argument and returns the output at this address. The problem is with KASLR we don't know which address to read. The thing is with aarch64 linux kernel, there is no randomization of the linear map section, and the kernel is loaded as a physical address. Here is an article of project zero which talks about it : https://googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html .
- To get code execution, we could trigger a buffer overflow in the kernel module but there is kernel stack canary. We need to use the arbitrary read to bypass the canary. The value of the canary is saved in the task_struct of the process, we need to cross the tasks to find the one related to our exploit process. The tricky thing is kernel is compiled with random structure layout : https://medium.com/@boutnaru/the-linux-kernel-macro-journey-randomize-layout-b611e4c597ff . It might breaks GDB plugins like the one from bata24. The initial idea of the challenge was to provide a different kernel in remote but it modified some offsets and made the exploit too hard for the CTF duration I think. (Forced player to dump the kernel in remote, etc.) So my exploit does some heuristics to find the offsets of the next field, canary and process name, but it's not necessary to solve the challenge. Once we find the task_struct of our exploit process and the canary we could control PC and do ROP.
- The ROP is a bit tricky, I choose to chain gadgets to execute prepare_kernel_creds and commit_creds. First we couldn't jump to linear map section because it's not executable so during our leak phase we need to find a pointer to a virtual pointer of the kernel to compute the kernel base. I use one after __start_rodata variable. We couldn't execute prepare_kernel_creds with 0 as argument to get cred struct for root user because the kernel code changed (recently I think ?) and forced a call with the task_struct to copy cred as argument. So we need to set the good argument in x0 with the first init_task. We also need to chain gadgets to restore the stack and go back to userland normally, as the program does without corruption.

The exploit is right [here](./exploit/exploit.c).

### Flag

Hero{e9ae08713bb1b4d486ca2f494f7562770a5fe82b}
