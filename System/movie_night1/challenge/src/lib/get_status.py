#!/usr/bin/env python3

"""
Get Status Script
Gets the current user and UID information as the dbus-service user
"""

import os
import pwd

def main():
    """Get service status information"""
    uid = os.getuid()
    try:
        user = pwd.getpwuid(uid).pw_name
    except:
        user = f"uid_{uid}"
    print(f"Service v2 running as: {user} (UID: {uid})")

if __name__ == "__main__":
    main()
