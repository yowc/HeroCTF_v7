#!/bin/bash

# Validate and sanitize user input
APPEND_OR_DELETE=$1
CHAIN=$2
PROTOCOL=$3
PORT_SRC=$4
PORT_DST=$5
ACTION=$6

# Define allowed chains, protocols, and actions
ALLOWED_APPEND_OR_DELETE=("A" "D")
ALLOWED_CHAINS=("INPUT" "OUTPUT" "FORWARD" "PREROUTING" "POSTROUTING")
ALLOWED_PROTOCOLS=("tcp" "udp")
ALLOWED_ACTIONS=("ACCEPT" "DROP" "REJECT" "MASQUERADE" "REDIRECT")

# Function to check if a value is in an array
containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

# Input validation
if ! containsElement "$APPEND_OR_DELETE" "${ALLOWED_APPEND_OR_DELETE[@]}"; then
    echo "Error: Invalid append or delete specified. Allowed values are: ${ALLOWED_APPEND_OR_DELETE[*]}"
    exit 1
fi

if ! containsElement "$CHAIN" "${ALLOWED_CHAINS[@]}"; then
    echo "Error: Invalid chain specified. Allowed chains are: ${ALLOWED_CHAINS[*]}"
    exit 1
fi

if ! containsElement "$PROTOCOL" "${ALLOWED_PROTOCOLS[@]}"; then
    echo "Error: Invalid protocol specified. Allowed protocols are: ${ALLOWED_PROTOCOLS[*]}"
    exit 1
fi

if ! [[ "$PORT_SRC" =~ ^[0-9]+$ ]] || ! [[ "$PORT_DST" =~ ^[0-9]+$ ]]; then
    echo "Error: Ports must be numbers."
    exit 1
fi

if [[ "$PORT_SRC" -lt 1 ]] || [[ "$PORT_SRC" -gt 2000 ]] || [[ "$PORT_DST" -lt 1 ]] || [[ "$PORT_DST" -gt 2000 ]]; then
    echo "Error: Ports must be between 1 and 2000 (inclusive)."
    exit 1
fi

if ! containsElement "$ACTION" "${ALLOWED_ACTIONS[@]}"; then
    echo "Error: Invalid action specified. Allowed actions are: ${ALLOWED_ACTIONS[*]}"
    exit 1
fi

# Build and execute the iptables command based on action
if [[ "$ACTION" == "REDIRECT" ]]; then
    /usr/sbin/iptables -t nat -$APPEND_OR_DELETE "$CHAIN" -p "$PROTOCOL" --dport "$PORT_SRC" -j "$ACTION" --to-ports "$PORT_DST"
    echo "Redirect rule added successfully: /usr/sbin/iptables -t nat -$APPEND_OR_DELETE  $CHAIN -p $PROTOCOL --dport $PORT_SRC -j $ACTION --to-ports $PORT_DST"
elif [[ "$ACTION" == "MASQUERADE" ]]; then
    /usr/sbin/iptables -t nat -$APPEND_OR_DELETE "$CHAIN" -j "$ACTION"
    echo "Masquerade rule added successfully: /usr/sbin/iptables -t nat -$APPEND_OR_DELETE  $CHAIN -j $ACTION"
else
    /usr/sbin/iptables -$APPEND_OR_DELETE "$CHAIN" -p "$PROTOCOL" --dport "$PORT_SRC" -j "$ACTION"
    echo "Rule added successfully: /usr/sbin/iptables -$APPEND_OR_DELETE  $CHAIN -p $PROTOCOL --dport $PORT_SRC -j $ACTION"
fi