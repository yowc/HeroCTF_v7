#!/bin/bash

function dc_up() {
    (cd "$1" && docker compose up -d --build)
}

dc_up "./Crypto/"
dc_up "./Prog/"
dc_up "./Reverse/"
dc_up "./Web/SAMLevinson/"