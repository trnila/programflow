#!/bin/bash
i=1
while read -r cmd; do
	echo "$cmd" $i
	eval "./graph out/$i $cmd"

	i=$((i+1))
done < tests

