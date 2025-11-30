#!/bin/bash

# Wrapper script to monitor and restart process_monitor if it crashes
# Logs restarts to /root/monitor-wrapper.log

MONITOR_BINARY="/root/process_monitor"
LOG_FILE="/root/process-monitor.log"
MAX_RESTARTS=1000  # Prevent infinite restart loops (safety limit)
RESTART_DELAY=2    # Wait 2 seconds before restarting

restart_count=0

while [ $restart_count -lt $MAX_RESTARTS ]; do
    echo "$(date): Starting process monitor (attempt $((restart_count + 1)))" >> /root/monitor-wrapper.log
    
    # Run the monitor binary
    "$MONITOR_BINARY" >> "$LOG_FILE" 2>&1
    exit_code=$?
    
    restart_count=$((restart_count + 1))
    
    # Log the crash
    echo "$(date): Process monitor exited with code $exit_code, restarting in ${RESTART_DELAY}s..." >> /root/monitor-wrapper.log
    
    # Wait before restarting
    sleep $RESTART_DELAY
done

echo "$(date): Maximum restart limit ($MAX_RESTARTS) reached, stopping monitor wrapper" >> /root/monitor-wrapper.log

