#include <thread>
#include <iostream>
#include <fstream>
#include <chrono>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/syscall.h>

void f(const char* name, int fd) {
	//std::this_thread::sleep_for(std::chrono::seconds(1));
	std::ifstream file(name);

	std::string line;
	while(std::getline(file, line)) {
		write(fd, line.c_str(), line.size());
		write(fd, "\n", 1);
		std::cout << line << '\n';
	}
}

void* fn(void*) {
	std::cout << "hello from pthread!\n";
}

int main() {
	int pipes[2];
	pipe(pipes);

	std::cout << getpid() << "-" << syscall(SYS_gettid) << "\n";

	std::thread t(f, "/etc/passwd", pipes[1]);
	std::thread t2(f, "/etc/hostname", pipes[1]);
	std::thread t4(f, "/proc/self/environ", pipes[1]);
	std::thread t3([=]() -> void {
		std::cout << "Thread 1\n";
		std::thread t4([=]() -> void {
			std::cout << "Thread 2\n";

			std::cout << getpid() << "-" << syscall(SYS_gettid) << "\n";
			//sleep(60000000);
			if(fork() == 0) {
				close(pipes[1]);
				dup2(pipes[0], 0);

				int out = open("/dev/null", O_WRONLY);
				dup2(out, 1);

				execlp("/usr/bin/tr", "/usr/bin/tr", "a-z", "A-Z", (char*) 0);
				perror("execl: ");
				exit(1);
			}

			while(wait(0) > 0);

		});
		t4.join();
	});

	t.join();
	t2.join();
	t4.join();
	close(pipes[1]);
	t3.join();

	pthread_t pt;
	pthread_create(&pt, 0, fn, 0);
}
