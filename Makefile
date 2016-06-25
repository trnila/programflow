LDFLAGS=-pthread
CC=g++

all: graph

graph: graph.o ./tracy/src/libtracy.a
