#!/bin/bash

for i in $(find . -name 'challenge.y*ml' -type f 2>/dev/null)
do
    echo "--------[ SYNC $i ]--------"
    # ctf challenge install "$PWD/$i"
	ctf challenge sync "$PWD/$i"
done

