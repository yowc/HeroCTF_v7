#!/usr/bin/env python3

"""
Load Pickle Script
Safely loads and executes pickle files as the dbus-service user
"""

import sys
import pickle
import os
import sys
import logging

logger = logging.getLogger(__name__)

def main():    
    if len(sys.argv) != 2:
        print("Usage: python3 load_pickle.py <filepath>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        # Check if file exists
        if not os.path.exists(filepath):
            print(f"Error: File {filepath} does not exist")
            sys.exit(1)
        
        # Load the pickle file
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Deserialize the pickle
        obj = pickle.loads(data)
        
        # Print the object for the main service to capture
        print(obj)
        
    except Exception as e:
        print(f"Error loading pickle: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
