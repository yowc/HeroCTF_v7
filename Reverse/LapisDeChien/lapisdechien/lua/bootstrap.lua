local lapis = require("lapis")
local db = require("lapis.db")

db.query([[
  CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(64) PRIMARY KEY,
    password VARCHAR(255) NOT NULL
  )
]])

local ok, app = pcall(require, "app")
if not ok then
  ngx.status = 500
  ngx.say("Failed to load app: " .. tostring(app))
  ngx.log(ngx.ERR, "Failed to load app: ", tostring(app))
  return
end

lapis.serve(app)