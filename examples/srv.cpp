#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	int srv = socket(AF_INET, SOCK_STREAM, 0);
	if(srv < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1234);
	addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(srv, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		perror("bind");
		exit(1);
	} 

	if(listen(srv, 1) != 0) {
		perror("listen");
		exit(1);
	}
	
	while(1) {
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int c = accept(srv, (struct sockaddr*) &client, &len);
		if(fork() == 0) {

		}
	}	
}
