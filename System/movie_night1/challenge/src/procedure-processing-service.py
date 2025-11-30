#!/usr/bin/env python3

"""
Procedure Processing Service
Accepts serialized Python objects for processing with procedure registration/execution
Running as root user via systemd service with TOCTOU vulnerability
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import base64
import subprocess
import os
import uuid
import logging
import glob
from lib.utils import get_caller_uid, execute_as_user, unpickle_file

# Set up logging
logging.basicConfig(level=logging.INFO, filename='/root/procedure-processing-service.log')
logger = logging.getLogger(__name__)

class ProcedureProcessingService(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.procedures_dir = "/var/procedures"
        logger.info("Procedure Processing Service started")
        
        # Ensure procedures directory exists and is owned by dbus-service
        if not os.path.exists(self.procedures_dir):
            os.makedirs(self.procedures_dir, mode=0o755)
            logger.info(f"Created procedures directory: {self.procedures_dir}")
        os.chown(self.procedures_dir, 1005, 1005)
        os.chmod(self.procedures_dir, 0o750)

    @dbus.service.method("com.system.ProcedureService", in_signature='ss', out_signature='s', sender_keyword='sender')
    def RegisterProcedure(self, name, serialized_code, sender=None):
        """
        Register a procedure with the given name and serialized code
        """
        logger.info(f"RegisterProcedure called with name: {name}")
        
        try:
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
            
            logger.info(f"Procedure registered: {filename} (owner: {caller_uid})")
            return f"Procedure '{name}' registered successfully"
            
        except Exception as e:
            logger.error(f"Error registering procedure: {e}")
            return f"Error: {e}"

    @dbus.service.method("com.system.ProcedureService", in_signature='', out_signature='as', sender_keyword='sender')
    def ListProcedures(self, sender=None):
        """
        List all procedures owned by the caller
        """
        logger.info("ListProcedures called")
        
        try:
            # Get caller UID
            caller_uid = get_caller_uid(sender)
            if caller_uid is None:
                return ["Error: Could not determine caller UID"]
            
            # List procedures owned by the caller based on file permissions
            procedures = []
            pattern = f"*.pkl"
            search_path = os.path.join(self.procedures_dir, pattern)
            for filepath in glob.glob(search_path):
                try:
                    file_stat = os.stat(filepath)
                    if file_stat.st_uid == caller_uid:
                        filename = os.path.basename(filepath)
                        procedure_name = "_".join(filename.split('_')[1:])[:-4]
                        procedures.append(procedure_name)
                except Exception as e:
                    logger.error(f"Error accessing file {filepath}: {e}")
            
            logger.info(f"Found {len(procedures)} procedures for UID {caller_uid}: {procedures}")
            return procedures
            
        except Exception as e:
            logger.error(f"Error listing procedures: {e}")
            return [f"Error: {e}"]

    @dbus.service.method("com.system.ProcedureService", in_signature='s', out_signature='s', sender_keyword='sender')
    def ExecuteProcedure(self, name, sender=None):
        """
        Execute a procedure
        """
        logger.info(f"ExecuteProcedure called with name: {name}")

        filepath = None
        try:
            # Find the file that matches the name pattern: <uuid4>_<name>.pkl
            pattern = os.path.join(self.procedures_dir, f"*_{name}.pkl")
            matching_files = glob.glob(pattern)
            if not matching_files:
                return f"Error: Procedure '{name}' not found"
            filepath = matching_files[0]

            if not os.path.exists(filepath):
                return f"Error: Procedure '{name}' not found"

            # Unpickle code
            obj_repr, error = unpickle_file(filepath)
            if error:
                return f"Unpickle error: {error}"

            # Check file ownership
            try:
                file_stat = os.stat(filepath)
                file_owner_uid = file_stat.st_uid
            except Exception as e:
                logger.error(f"File ownership check failed: {e}")
                return f"Error: Could not check file ownership - {e}"

            # Execute code with the correct permissions
            # Must be the owner, since we can't list other users' procedures
            result = execute_as_user(obj_repr, file_owner_uid)

            return result

        except Exception as e:
            logger.error(f"Error executing procedure: {e}")
            return f"Error: {e}"

        finally:
            if filepath and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    logger.info(f"Deleted procedure file: {filepath}")
                except Exception as e:
                    logger.warning(f"Could not delete procedure file: {e}")

    @dbus.service.method("com.system.ProcedureService", in_signature='s', out_signature='s', sender_keyword='sender')
    def RemoveProcedure(self, name, sender=None):
        """
        Remove a procedure owned by the caller
        """
        logger.info(f"RemoveProcedure called with name: {name}")
        
        try:
            # Get caller UID
            caller_uid = get_caller_uid(sender)
            if caller_uid is None:
                return "Error: Could not determine caller UID"
            
            # Find the file that matches the name pattern: <uuid4>_<name>.pkl
            pattern = os.path.join(self.procedures_dir, f"*_{name}.pkl")
            matching_files = glob.glob(pattern)
            if not matching_files:
                return f"Error: Procedure '{name}' not found"
            
            filepath = matching_files[0]
            
            # Check if file exists
            if not os.path.exists(filepath):
                return f"Error: Procedure '{name}' not found"
            
            # Check file ownership - only the owner can remove their procedure
            try:
                file_stat = os.stat(filepath)
                file_owner_uid = file_stat.st_uid
            except Exception as e:
                logger.error(f"File ownership check failed: {e}")
                return f"Error: Could not check file ownership - {e}"
            
            # Verify the caller owns this procedure
            if file_owner_uid != caller_uid:
                logger.warning(f"User {caller_uid} attempted to remove procedure owned by {file_owner_uid}")
                return f"Error: You can only remove your own procedures"
            
            # Remove the procedure file
            try:
                os.remove(filepath)
                logger.info(f"Procedure '{name}' removed successfully by user {caller_uid}")
                return f"Procedure '{name}' removed successfully"
            except Exception as e:
                logger.error(f"Error removing procedure file: {e}")
                return f"Error: Could not remove procedure - {e}"
            
        except Exception as e:
            logger.error(f"Error removing procedure: {e}")
            return f"Error: {e}"

    @dbus.service.method("com.system.ProcedureService", in_signature='', out_signature='s')
    def GetStatus(self):
        """Helper method to get service status as dbus-service user"""
        try:
            # Get the status as the dbus-service user
            lib_path = "/opt/procservice/lib/get_status.py"
            cmd = ['sudo', '-u', 'dbus-service', 'python3', lib_path]
            
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=10)
            
            if process.returncode != 0:
                logger.error(f"GetStatus failed: {stderr}")
                return f"GetStatus error: {stderr}"
            
            # Get the status from the output of the subprocess
            status = stdout.strip()
            return status
            
        except subprocess.TimeoutExpired:
            logger.error("GetStatus timed out")
            return "GetStatus timed out"
        except Exception as e:
            logger.error(f"GetStatus error: {e}")
            return f"GetStatus error: {e}"

def main():
    # Set up DBUS
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    # Connect to system bus
    bus = dbus.SystemBus()
    # Request service name
    bus_name = dbus.service.BusName("com.system.ProcedureService", bus)
    # Create service object
    service = ProcedureProcessingService(bus, "/com/system/ProcedureService")
    logger.info("Procedure Processing Service ready, entering main loop")
    
    # Start main loop
    mainloop = GLib.MainLoop()
    mainloop.run()

if __name__ == "__main__":
    main()
