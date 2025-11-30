import dbus
import pwd
import subprocess
import logging
import shlex

logger = logging.getLogger(__name__)

def get_caller_uid(sender=None):
    """Get the UID of the caller"""
    bus = dbus.SystemBus()
    dbus_daemon = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    dbus_iface = dbus.Interface(dbus_daemon, 'org.freedesktop.DBus')

    # Query the UID of the sender
    uid = dbus_iface.GetConnectionUnixUser(sender)
    return uid

def get_username_by_uid(uid):
    """Resolve the username of a UID"""
    return pwd.getpwuid(uid).pw_name


def execute_as_user(code, uid):
    """
    Execute code as the specified user
    """
    try:
        # Security: never execute anything as root
        if uid == 0:
            logger.error("Cannot execute as root")
            return "Cannot execute as root"
        
        username = get_username_by_uid(uid)
        cmd = ['sudo', '-u', username, 'python3', '-']
        
        logger.info(f"Executing as {username} (UID {uid}) via stdin")
        logger.info(f"Executing code: {code}")
        
        # Execute with stdin input
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Send code via stdin and get output
        stdout, stderr = process.communicate(input=code, timeout=0.5)

        logger.info(f"Execution output: {stdout}")
        logger.info(f"Execution error: {stderr}")
        logger.info(f"Execution return code: {process.returncode}")
        
        if process.returncode != 0:
            logger.error(f"Execution failed: {stderr}")
            return f"Execution error: {stderr}"
        
        return stdout
        
    except subprocess.TimeoutExpired:
        logger.error("Execution timed out")
        return "Execution timed out"
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return f"Execution error: {e}"

def unpickle_file(filepath):
    """
    Unpickle the file as the dbus-service user using lib/load_pickle.py
    """
    try:
        # Unpickle the file as the dbus-service user using lib/load_pickle.py
        lib_path = "/opt/procservice/lib/load_pickle.py"
        cmd = ['sudo', '-u', 'dbus-service', 'python3', lib_path, filepath]
        
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=filepath, timeout=0.5)
        return stdout, None
        
    except subprocess.TimeoutExpired:
        logger.error("Unpickle timed out")
        return None, "Unpickle timed out"
    except Exception as e:
        logger.error(f"Unpickle error: {e}")
        return None, f"Unpickle error: {e}"