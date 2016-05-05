#!/bin/bash

for file in `ls zones`;
do
	for line in `cat zones/$file | grep -v TXT | grep NS | sed s/[[:space:]]*NS\[[:space:]]*/,/`;
	do
		domain=$(echo $line | cut -f1 -d ',')
		ns=$(echo $line | cut -f2 -d ',')

		sh try-get-zone.sh $domain $ns >> out/$file.out
	done
done
