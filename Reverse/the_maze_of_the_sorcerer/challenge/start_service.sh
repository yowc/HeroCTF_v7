#!/bin/bash

while :
do
    su -c "exec socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork EXEC:'/usr/local/bin/run_challenge.sh,stderr'" - challenge;
done