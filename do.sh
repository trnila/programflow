make -C tracy/src/ clean default && make && clear && ./graph /tmp/graph "$@" && dot -Tsvg /tmp/graph/graph.dot > /tmp/graph/graph.svg
