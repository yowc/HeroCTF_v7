#!/bin/bash

# Create and configure SSH directory
mkdir -p /var/run/sshd
chmod 0755 /var/run/sshd

# Start DBUS daemon
echo "Starting DBUS daemon..."
mkdir -p /var/run/dbus
dbus-daemon --system --fork

# Wait for DBUS to be ready
sleep 2

# Start the vulnerable Python DBUS service as root
echo "Starting vulnerable DBUS service..."
nohup /usr/bin/python3 /opt/procservice/procedure-processing-service.py > /root/procedure-processing-service.log 2>&1 &

# Wait for service to initialize
sleep 2

# Start process monitor as root to enforce security restrictions (with auto-restart)
echo "Starting process monitor..."
nohup /root/monitor_wrapper.sh > /root/monitor-wrapper.log 2>&1 &

# Wait for monitor to initialize
sleep 1

# Set up tmux session as dev
echo "Setting up tmux session for dev..."
TMUX_SOCKET="/tmp/tmux-1002"

# Create tmux session as dev in /opt/procservice directory
su - dev -c "tmux -S ${TMUX_SOCKET} new-session -d -s work 'bash'"

# Set socket permissions to world-accessible
chmod 666 ${TMUX_SOCKET}

echo "Tmux session created at ${TMUX_SOCKET}"
echo "Service environment ready!"

# Start SSH daemon (blocking)
echo "Starting SSH daemon..."
/usr/sbin/sshd -D

