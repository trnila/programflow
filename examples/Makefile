all: pipes dbus unixsocket c++11threads

dbus: dbus.cpp
	g++ dbus.cpp -o dbus `pkg-config --cflags --libs libsystemd`

c++11threads: c++11threads.cpp
	g++ $^ -o $@ -pthread

clean:
	rm -f *.o pipes dbus unixsocket
