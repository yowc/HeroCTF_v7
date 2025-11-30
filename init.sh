#!/usr/bin/env bash
 
categories=( Crypto Forensics Misc Prog Pwn Reverse Steganography System Web )

for category in "${categories[@]}"
do
    mkdir $category
    touch $category/.gitkeep
done

echo "Done !"