#!/bin/sh

echo "${FLAG:-HEROCTF_FAKE_FLAG}" > /flag.txt
chmod 444 /flag.txt
unset FLAG

/usr/local/openresty/bin/openresty -g 'daemon off;'