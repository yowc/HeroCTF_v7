local db = require("lapis.db")
local lfs = require("lfs")

local utils = require("utils")

local _M = {}

function _M.login(self)
  local username = self.params.username or ""
  local password = self.params.password or ""

  if username == "" or password == "" then
    return { status = 400, json = { message = "Username and password are required" } }
  end

  local res = db.query("SELECT * FROM users WHERE ?", db.clause({
    username = username,
    password = password
  }))

  if #res == 0 then
    return { status = 401, json = { message = "Invalid username or password" } }
  end

  self.session.authenticated = true
  self.session.username = username

  return { status = 200, json = { message = "User logged" } } 
end

function _M.register(self)
  local username = self.params.username or ""
  local password = self.params.password or ""

  if username == "" or password == "" then
    return { status = 400, json = { message = "Username and password are required" } }
  end

  if string.find(username, "/") or string.find(username, "\\") then
    return { status = 400, json = { message = "Invalid username" } }
  end

  local res = db.query("SELECT * FROM users WHERE ?", db.clause({
    username = username
  }))

  if #res > 0 then
    return { status = 409, json = { message = "Username already exists" } }
  end

  db.query("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
  lfs.mkdir("public/" .. username)

  return { status = 200, json = { message = "User registered" } } 
end

function _M.delete(self)
  local directory = "public/" .. self.session.username

  if utils.is_dir(directory) then
    utils.rm_dir(directory)
  end

  self.session.authenticated = false
  self.session.username = ""

  return { status = 200, json = { message = "User removed" } } 
end

return _M