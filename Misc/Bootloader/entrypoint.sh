#!/bin/sh
set -e

PORT=${PORT:-4000}

# Pour chaque connexion TCP, socat lance qemu_wrapper.sh
socat TCP-LISTEN:${PORT},reuseaddr,fork \
  EXEC:/challenge/qemu_wrapper.sh,pty,stderr
