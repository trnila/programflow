make -C tracy/src/ clean default && make && clear && ./graph "$@"; /home/daniel/graphviz/bin/dot -Tsvg /tmp/graph.dot > /tmp/a.svg
