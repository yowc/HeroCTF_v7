#!/bin/bash

echo "${FLAG:-HEROCTF_FAKE_FLAG}" > "/app/flag_$(openssl rand -hex 8).txt"
chmod 444 /app/flag_*.txt
unset FLAG

/app/cracker/cracker &
cd /app/api/ && ./api