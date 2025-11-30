#!/bin/bash

echo "${FLAG:-HEROCTF_FAKE_FLAG}" > "/app/flag_$(openssl rand -hex 8).txt"

/usr/bin/supervisord -n