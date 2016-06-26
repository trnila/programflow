#!/bin/bash
list=out/out.html

n=1
echo "<ul>" > $list
for i in out/*.dot; do
	/home/daniel/graphviz/bin/dot -Tsvg "$i" > "$(dirname "$i")/$(basename "$i" .dot).svg"

	name=$(sed "${n}q;d" tests)
	echo "<li><a href='$n.svg'>$name</a></li>" >> $list
	
	n=$((n+1))
done;
echo "</ul>" >> $list
