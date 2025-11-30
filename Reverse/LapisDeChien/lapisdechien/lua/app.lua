local lapis = require("lapis")
local json_params = require("lapis.application").json_params

local middleware = require("middleware")
local user_controller = require("controllers.user")
local file_controller = require("controllers.file")

local app = lapis.Application()

app:before_filter(middleware.login_required)
app:before_filter(middleware.enforce_json)

app:post("/user/login", json_params(user_controller.login))
app:post("/user/register", json_params(user_controller.register))
app:delete("/user/delete", json_params(user_controller.delete))

app:post("/file/upload", json_params(file_controller.upload))
app:delete("/file/remove", json_params(file_controller.remove))

function app:handle_404()
  return { status = 404, json = { message = "Failed to find route: " .. self.req.request_uri } }
end

function app:handle_error(err, trace)
  return { status = 500, json = { message = tostring(err) .. trace } }
end

return app