#!/bin/bash
list=out/index.html

echo "<ul>" > $list
for i in $(find out -type f -name "*.dot"); do
	dot -Tsvg "$i" > "$(dirname "$i")/graph.svg"

	n=$(basename "$(dirname "$i")")
	name=$(sed "${n}q;d" tests)
	echo "<li><a href='$n/graph.svg'>$name</a></li>" >> $list
done;
echo "</ul>" >> $list
