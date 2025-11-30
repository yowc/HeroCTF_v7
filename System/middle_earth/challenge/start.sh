#!/bin/bash

python3 /challenge/app.py&
mkdir /var/run/sshd
chmod 0755 /var/run/sshd
/usr/sbin/sshd -D