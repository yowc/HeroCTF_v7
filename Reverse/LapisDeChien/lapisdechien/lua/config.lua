local config = require("lapis.config")

config({"development", "production"}, {
  port = 80,
  session_name = "lapis_session",
  secret = os.getenv("SECRET"),
  sqlite = {
    database = ":memory:"
  }
})