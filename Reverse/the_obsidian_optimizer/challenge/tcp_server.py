#!/usr/bin/env python3
import socket
import subprocess
import sys
import os

def handle_client(conn):
    """Handle a single client connection"""
    try:
        # Set a timeout for receiving data
        conn.settimeout(2.0)

        # Receive all data from client
        data = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                # No more data coming, proceed
                break

        # Verify we received data
        if not data:
            conn.sendall(b"Error: No data received\n")
            return

        # Run the challenge script with the data as stdin
        proc = subprocess.Popen(
            ['/bin/bash', '/usr/local/bin/run_challenge.sh'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd='/home/challenge',
            bufsize=0  # Unbuffered
        )

        # Send input and get all output
        output, _ = proc.communicate(input=data, timeout=60)

        # Send all output back to client
        conn.sendall(output)

        # Ensure all data is flushed
        conn.shutdown(socket.SHUT_WR)

    except subprocess.TimeoutExpired:
        conn.sendall(b"Error: Process timeout\n")
    except Exception as e:
        conn.sendall(f"Error: {str(e)}\n".encode())
    finally:
        conn.close()

def main():
    port = int(os.environ.get('LISTEN_PORT', 1337))

    # Create socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)

    print(f"Listening on port {port}")
    sys.stdout.flush()

    while True:
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        sys.stdout.flush()
        handle_client(conn)

if __name__ == '__main__':
    main()
