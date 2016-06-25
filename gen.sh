#!/bin/bash

for i in out/*.dot; do
	/home/daniel/graphviz/bin/dot -Tsvg "$i" > "$(dirname "$i")/$(basename "$i" .dot).svg"
done;
