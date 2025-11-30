
#!/bin/bash
# Compile and replace all Lua source files by their LuaJIT bytecode equivalents

set -eu

if ! command -v luajit >/dev/null 2>&1; then
  echo "ERROR: luajit not found in PATH"
  exit 2
fi

git -C /tmp/ clone https://github.com/prometheus-lua/Prometheus.git && \
  pushd /tmp/Prometheus/ && \
  git checkout v0.2.7 && \
  popd

mkdir -p ./dist/controllers/ ./dist/public/

find ./lua/ -type f -name '*.lua' -print0 | while IFS= read -r -d '' source; do
  echo "Compiling $source"

  obfuscated="${source:0:-4}.obfuscated.lua"
  compiled="./dist/${source:6}"

  lua /tmp/Prometheus/cli.lua --preset Medium "$source"
  luajit -b "$obfuscated" "$compiled"
  rm "$obfuscated"
done

echo "Compilation complete."