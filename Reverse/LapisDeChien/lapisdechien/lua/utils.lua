local lfs = require("lfs")

local _M = {}

function _M.is_dir(path)
    local cd = lfs.currentdir()
    local is = lfs.chdir(path) and true or false
    lfs.chdir(cd)
    return is
end

function _M.rm_dir(path)
    os.execute(("rm -r '%s'"):format(path))
end

return _M