#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main() {
	int outer[2];
	pipe(outer);
	if(fork() == 0) {
		int inner[2];
		pipe(inner);
		if(fork() == 0) {
			const char* text="hello!";	
			write(inner[1], text, strlen(text));
			exit(0);
		}
		close(inner[1]);

		char buffer[100];
		int r;
		while(r = read(inner[0], buffer, sizeof(buffer))) {
			for(int i = 0; i < r; i++) {
				if(buffer[i] >= 'a' && buffer[i] <= 'z') {
					buffer[i] = buffer[i] - ('z' - 'Z');
				}
			}
			write(outer[1], buffer, r);
		}
		exit(0);
	}
	close(outer[1]);

	char buffer[100];
	int r;
	while(r = read(outer[0], buffer, sizeof(buffer))) {
		write(1, buffer, r);
	}
}
