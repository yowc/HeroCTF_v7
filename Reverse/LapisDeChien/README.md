# Lapis De Chien

### Category

Reverse

### Difficulty

Medium

### Tags

- web
- lua

### Author

xanhacks

### Description

Your task is to audit the following web application in a black-box setting. The client has explicitly requested that you not be provided with the source code, as they want you to simulate the role of an external attacker.

Reverse the target application and identify a basic web vulnerability that allows you to retrieve the flag.

Download the application's container: [lapisdechien.tar](https://heroctf.fr-par-1.linodeobjects.com/lapisdechien.tar)

> MD5(lapisdechien.tar) = 2d70b6ef3ccf4114b12d004cc5092a47

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Write Up

#### Static Analysis

The target application runs **OpenResty** (an **Nginx** fork with the **LuaJIT** interpreter), with Lua scripts located in:
`/usr/local/openresty/nginx/lua/`

```bash
challenge:/usr/local/openresty/nginx/lua# find . -name '*.lua'
./config.lua
./utils.lua
./controllers/user.lua
./controllers/file.lua
./bootstrap.lua
./app.lua
./middleware.lua
challenge:/usr/local/openresty/nginx/lua# xxd app.lua | head -n1
00000000: 1b4c 4a02 0a1c 0001 0301 0001 042d 0100  .LJ..........-..
```

All scripts are **LuaJIT-compiled** (magic bytes: **`1b 4c 4a`**). To decompile them, you can use the **[LuaJIT Decompiler](https://gitlab.com/znixian/luajit-decompiler/)**.

```lua
challenge:/usr/local/openresty/nginx/lua# python3 luajit-decompiler/main.py app.lua
return function (...)
        slot0 = {
                "kfDJXP==",
                "zJ05kis=",
                "EzdK4gL5M0qh/HU=",
                "cSUOPxK1rvBs3kXTX+XlwV==",
                "6nPqkbBM6P==",
                "pNI=",
                "9cgfjtjy",
                "E9wjka+CvrjkkJWaDEI=",
-- Skipping...                
                return function (slot0, slot1)
                        slot2 = uv0(slot1)

                        return function (...)
                                return uv0(uv1, {
                                        ...
                                }, uv2, uv3)
                        end
                end(13683770, {})(slot1(slot6))
        end(getfenv and getfenv() or _ENV, unpack or table[slot1(27619)], newproxy, setmetatable, getmetatable, select, {
                ...
        })
end(...)
```

After researching **Lua obfuscation**, you may encounter the **[Prometheus obfuscator](https://github.com/prometheus-lua/Prometheus)**. Since there is **no straightforward method** to reverse-engineer its output, we will proceed with **dynamic analysis** instead.

#### Dynamic Analysis

The target application appears to use the **`Lapis` framework**, as evidenced by:
- **`strace` output**, or
- **Dockerfile history inspection**.

```bash
challenge:/usr/local/openresty/nginx/lua# strace -e open luajit app.lua 2>&1 | grep lapis | grep -v ENOENT | sort | uniq
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/application.lua", O_RDONLY|O_LARGEFILE) = 3
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/application/route_group.lua", O_RDONLY|O_LARGEFILE) = 3
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/config.lua", O_RDONLY|O_LARGEFILE) = 3
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/coroutine.lua", O_RDONLY|O_LARGEFILE) = 3
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/db.lua", O_RDONLY|O_LARGEFILE) = 3
open("/usr/local/openresty/luajit/share/lua/5.1/lapis/db/base.lua", O_RDONLY|O_LARGEFILE) = 3
...
```

```bash
$ sudo docker history lapisdechien --no-trunc | grep 'apk add' | head -n1
RUN /bin/sh -c apk add --no-cache     bash findutils sqlite sqlite-dev     git wget curl ca-certificates     lua5.1 build-base openssl-dev pcre-dev zlib-dev &&     luarocks install lapis &&     luarocks install luafilesystem &&     luarocks install lsqlite3
```

##### Logging in Lapis framework

1. Add log using `local logger = require("lapis.logging")`
2. Switch NGINX log level `error_log logs/error.log notice;`
3. Reload web server with `openresty -s reload`

Logs all routes definition inside `/usr/local/openresty/luajit/share/lua/5.1/lapis/application.lua`:

```lua
  local _list_0 = {
    "get",
    "post",
    "delete",
    "put"
  }
  for _index_0 = 1, #_list_0 do
    local meth = _list_0[_index_0]
    local upper_meth = meth:upper()
    self.__base[meth] = function(self, route_name, path, handler)
      logger.notice("ROUTE => " .. upper_meth .. " " .. route_name)
      self.router = nil
```

Obtain all the routes:

```bash
... [notice] 131#131: *3 [lua] application.lua:357: Notice: ROUTE => POST /user/login, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
... [notice] 131#131: *3 [lua] application.lua:357: Notice: ROUTE => POST /user/register, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
... [notice] 131#131: *3 [lua] application.lua:357: Notice: ROUTE => DELETE /user/delete, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
... [notice] 131#131: *3 [lua] application.lua:357: Notice: ROUTE => POST /file/upload, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
... [notice] 131#131: *3 [lua] application.lua:357: Notice: ROUTE => DELETE /file/remove, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
... [notice] 131#131: *3 [lua] [C]:-1: [401] GET / - {  }, client: 172.19.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8000"
```

Logs all `self.session` access/write in `/usr/local/openresty/luajit/share/lua/5.1/lapis/session.lua`:

```lua
  local __newindex
  __newindex = function(self, key, val)
    insert(getmetatable(self), key)
    logger.notice("SET session." .. key .. " => " .. tostring(val))
    return rawset(self, key, val)
  end
  local __index
  __index = function(self, key)
    local mt = getmetatable(self)
    local s = mt.get_session(mt.req) or { }
    logger.notice("GET session." .. key .. " => " .. tostring(s[key]))
    mt.__index = s
    return s[key]
  end
```

The API returns detailed error messages, which can be used to create the expected JSON structure for HTTP request.

```bash

$ curl -H 'Content-type: application/json' -X POST http://localhost:8000/user/register
{"message":"Username and password are required"}%
$ curl -H 'Content-type: application/json' -X POST http://localhost:8000/user/register -d '{"username":"foo", "password": "bar"}'
{"message":"User registered"}
```

##### Trace OpenResty worker

After tracing system calls, we observe that the `DELETE /user/delete` endpoint executes a shell command incorporating the **username** parameter. It can be exploited to run arbitrary shell commands and retrieve the flag.

```bash
$ ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 {openresty} nginx: master process /usr/local/openresty/bin/openresty -g daemon off;
    7 nobody    0:00 {openresty} nginx: worker process
    8 root      0:00 ash
   69 root      0:00 ps aux
$ strace -p 7 --follow-forks -e open,recvfrom,writev,write,stat,execve
strace: Process 7 attached
recvfrom(3, "DELETE /user/delete HTTP/1.1\r\nHo"..., 1024, 0, NULL, NULL) = 246
write(5, "2025/10/21 18:10:31 [notice] 7#7"..., 311) = 311
strace: Process 85 attached
[pid    85] execve("/bin/sh", ["sh", "-c", "rm -rf 'public/foobar'"], 0x7fa386490590 /* 2 vars */) = 0
[pid    85] write(1, "public/foobar\n", 14) = 14
[pid    85] +++ exited with 0 +++
write(5, "2025/10/21 18:10:31 [notice] 7#7"..., 211) = 211
writev(3, [{iov_base="HTTP/1.1 200 OK\r\nServer: openres"..., iov_len=300}, {iov_base="1a\r\n", iov_len=4}, {iov_base="{\"message\":\"User removed\"}", iov_len=26}, {iov_base="\r\n", iov_len=2}, {iov_base="0\r\n\r\n", iov_len=5}], 5) = 337
write(4, "172.18.0.1 - - [21/Oct/2025:18:1"..., 100) = 100
recvfrom(3, "", 1024, 0, NULL, NULL)    = 0
```

Solve script at [./solve.py](./solve.py)

### Flag

Hero{714be12cafa742bd1dd4f8b554d755e5}