LDFLAGS=-pthread
CC=g++
CXXFLAGS=-g

all: graph

./tracy/src/libtracy.a: 
	make -C tracy/src

graph: graph.o utils.o hooks.o processes.o tracy/src/libtracy.a

clean:
	rm -f graph *.o
