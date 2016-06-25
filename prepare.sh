#!/bin/bash
i=1
while read -r cmd; do
	echo "$cmd" $i
	OUT="out/$i.dot" eval "./graph $cmd"

	i=$((i+1))
done < tests

