#!/usr/bin/env python3

import argparse
import os
import sys

CONFIG_FILE = "settings.conf"

def read_config():
    """
    Reads the configuration from settings.conf and prints it.
    """
    print(f"[INFO] Reading configuration from '{CONFIG_FILE}'...")
    if not os.path.exists(CONFIG_FILE):
        print(f"[WARN] Configuration file not found. Nothing to read.")
        return

    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            # Skip comments and empty lines
            if line.strip().startswith('#') or not line.strip():
                continue
            print(f"  -> {line.strip()}")
    print("[INFO] Finished reading config.")

def write_config(key, value):
    """
    Writes a key-value pair to the configuration file.
    """
    print(f"[INFO] Writing '{key}={value}' to '{CONFIG_FILE}'...")
    with open(CONFIG_FILE, 'a') as f:
        f.write(f"{key}={value}\n")
    print("[INFO] Write operation successful.")

def main():
    """
    Main function to parse arguments and call the appropriate action.
    """
    parser = argparse.ArgumentParser(
        description="A simple tool to manage application configuration."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Parser for the "read" command
    parser_read = subparsers.add_parser("read", help="Read all settings from the config file.")
    
    # Parser for the "write" command
    parser_write = subparsers.add_parser("write", help="Write a new key-value setting.")
    parser_write.add_argument("key", type=str, help="The configuration key.")
    parser_write.add_argument("value", type=str, help="The configuration value.")

    args = parser.parse_args()

    if args.command == "read":
        read_config()
    elif args.command == "write":
        write_config(args.key, args.value)
    else:
        # If no command is given, print help
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()