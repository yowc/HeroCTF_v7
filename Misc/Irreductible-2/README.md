# Irreductible 2

### Category

Misc

### Difficulty

Medium

### Author

Alol

### Description

Instead of writing my own security library I'll use popular ones, surely they'll make my code secure... oh, *oh no*.

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Files

- [irreductible-2.zip](irreductible-2.zip)

### Write up

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

### Flag

Hero{M4yb3_4b4nd0n1ng_p1ckl3_4ll_70g37h3r_w0uld_b3_4_g00d_1d34}