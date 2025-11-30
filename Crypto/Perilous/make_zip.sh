#!/bin/sh

chall_name="perilous"

rm $chall_name.zip
mkdir $chall_name
echo "Hero{FAKE_FLAG}" >> $chall_name/flag.txt
cp chall.py $chall_name
cp entry.sh $chall_name
cp Dockerfile $chall_name
zip -r $chall_name.zip $chall_name
rm -rf $chall_name
