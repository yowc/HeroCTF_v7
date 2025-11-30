local _M = {}

function _M.login_required(self)
  local guest_routes = {
    "/user/login",
    "/user/register"
  }

  for _, route in ipairs(guest_routes) do
    if self.req.parsed_url.path == route then
      return
    end
  end

  if not self.session.authenticated then
    self:write({ status = 401, json = { message = "Authentication required" } })
  end
end

function _M.enforce_json(self)
  local content_type = self.req.headers["Content-Type"] or ""
  
  if string.find(content_type, "application/json") == nil then
    self:write({ status = 415, json = { message = "Content-Type must be application/json" } })
  end
end

return _M