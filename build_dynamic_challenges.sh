#!/bin/bash

PWD=$(pwd)

function build() {
    path=$1
    image_name=$2

    pushd "${PWD}/${path}"
    docker build . -t "$image_name"
    popd
}

# Image tag supports does not support uppercase letters
docker pull mysql:8.0 # Evil Cloner needs mysql

build "./Misc/Irreductible-2/" "irreductible_2:latest"
build "./Misc/neverland/challenge/" "neverland:latest"
build "./Misc/Bootloader/" "bootloader:latest"

build "./System/movie_night1/challenge/" "movie_night:latest"
build "./System/middle_earth/challenge/" "middle_earth:latest"
build "./System/middle_earth/bot/" "middle_earth_bot:latest"

build "./Pwn/Safe_device/infra/" "safe_device:latest"
build "./Pwn/PafTraversal/paf_traversal/" "paf_traversal:latest"
build "./Pwn/Identity/infra/" "identity:latest"
build "./Pwn/Storycontest/infra/" "storycontest:latest"
build "./Pwn/Crash/infra/" "crash:latest"

build "./Reverse/LapisDeChien/lapisdechien/" "lapisdechien:latest"
build "./Reverse/rusty_pool_party/rusty_pool_party/" "rusty_pool_party:latest"

build "./Web/Tomwhat/challenge/" "tomwhat:latest"
build "./Web/Spring_Drive/spring_drive/" "spring_drive:latest"
build "./Web/revoked/challenge/" "revoked:latest"
build "./Web/revoked_revenge/challenge/" "revoked_revenge:latest"
build "./Web/Evil_Cloner/challenge/" "evil_cloner:latest"
