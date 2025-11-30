local os = require("os")

local _M = {}

function _M.upload(self)
  local filename = self.params.filename or ""
  local filedata = self.params.filedata or ""

  if filename == "" or filedata == "" then
    return { status = 400, json = { message = "Filename, and filedata are required" } }
  end

  if string.find(filename, "/") or string.find(filename, "\\") then
    return { status = 400, json = { message = "Invalid filename" } }
  end

  local filepath = "public/" .. self.session.username .. "/" .. filename
  local file, err = io.open(filepath, "wb")
  if not file then
    return { status = 500, json = { message = "Failed to open file: " .. err } }
  end

  file:write(filedata)
  file:close()

  return { status = 200, json = { message = "File uploaded successfully", data = "/" .. filepath } } 
end

function _M.remove(self)
  local filename = self.params.filename or ""

  if filename == "" then
    return { status = 400, json = { message = "Filename is required" } }
  end

  if string.find(filename, "/") or string.find(filename, "\\") then
    return { status = 400, json = { message = "Invalid filename" } }
  end

  local filepath = "public/" .. self.session.username .. "/" .. filename
  local file, err = io.open(filepath, "rb")
  if not file then
    return { status = 404, json = { message = "File not found: " .. err } }
  end
  file:close()

  os.remove(filepath)

  return { status = 200, json = { message = "File removed successfully" } } 
end

return _M