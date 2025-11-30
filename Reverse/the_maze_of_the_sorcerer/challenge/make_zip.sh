#!/bin/sh

chall_name="maze"

mkdir -p $chall_name
mkdir -p $chall_name/src
mkdir -p $chall_name/bin
echo "Hero{FAKE_FLAG}" >> $chall_name/flag.txt
cp bin/the_maze_of_the_sorcerer.so $chall_name/bin
cp Makefile_player $chall_name/Makefile
cp src/valid_pass_template.c $chall_name/src/valid_pass.c
cp solve_template.py $chall_name
cp player_dock $chall_name/Dockerfile
zip -r $chall_name.zip $chall_name
rm -rf $chall_name
mv $chall_name.zip ../
