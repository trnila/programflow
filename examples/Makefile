all: pipes dbus

dbus:
	g++ dbus.cpp -o dbus `pkg-config --cflags --libs libsystemd`

clean:
	rm -f *.o pipes
