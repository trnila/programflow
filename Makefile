LDFLAGS=-pthread
CC=g++
CXXFLAGS=-g

all: graph

graph: graph.o ./tracy/src/libtracy.a base64.o
