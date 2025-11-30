#!/bin/bash

# Run Python TCP server as challenge user
exec su -s /bin/bash - challenge -c "python3 /usr/local/bin/tcp_server.py"
