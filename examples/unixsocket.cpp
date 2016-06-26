#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	int srv = socket(AF_UNIX, SOCK_STREAM, 0);
	if(srv < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/mysrv.sock");
	unlink("/tmp/mysrv.sock");

	if(bind(srv, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		perror("bind");
		exit(1);
	} 

	if(listen(srv, 1) != 0) {
		perror("listen");
		exit(1);
	}
	
	while(1) {
		struct sockaddr_un client;
		socklen_t len = sizeof(client);
		int c = accept(srv, (struct sockaddr*) &client, &len);
		if(fork() == 0) {
			char buffer[100];
			int r;
			while(r = read(c, buffer, sizeof(buffer))) {
				for(int i = 0; i < strlen(buffer); i++) {
					if(buffer[i] >= 'a' && buffer[i] <= 'z') {
						buffer[i] -= 'a' - 'A';
					}
				}
				write(c, buffer, strlen(buffer));
			}
		}
		close(c);
	}	
}
