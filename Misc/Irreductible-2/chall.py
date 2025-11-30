#!/usr/bin/env python3
import io
import fickling
from picklescan import scanner


# This time we're not taking any chances, we'll use proper scanning libraries
def hacking_attempt(m):
    s = scanner.scan_pickle_bytes(m, None)
    m.seek(0)
    return s.issues_count > 0


m = io.BytesIO(bytes.fromhex(input("🥒 : ")))

if not hacking_attempt(m):
    # second check, just to be extra careful
    fickling.load(m)
