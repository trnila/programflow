#include <stdlib.h>
#include <stdio.h>
#include <unordered_map>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include <cctype>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <asm/unistd.h>
#include <math.h>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <netinet/in.h>
#include <iostream>
#include "base64.h"
#include "malloc.h"

extern "C" {
	#include "tracy/src/tracy.h"
}

typedef struct {
	int size;
	char* data;
} content;

FILE* graph;

typedef struct _Process {
	pid_t parent = -1;
	std::string fds[50];
	std::unordered_map<std::string, content> contents;
	std::unordered_map<std::string, content> writes;

	_Process() {
		for(int i = 0; i < 50; i++) {
			fds[i] = std::to_string(i);
		}
	}
} Process;

std::unordered_map<pid_t, Process> processes;

Process& get(pid_t pid) {
	auto it = processes.find(pid);
	if(it != processes.end()) {
		return it->second;
	}

	processes[pid] = Process();
	return processes[pid];
}

void addFD(std::unordered_map<std::string, content> &map, std::string file, char* data, int size) {
	auto it = map.find(file);
	if(it != map.end()) {
		int pos = map[file].size;
		map[file].size += size;
		map[file].data = (char*) realloc(map[file].data, map[file].size);
		memcpy(map[file].data + pos, data, size);
	} else {
		map[file] = content();
		map[file].size = size;
		map[file].data = (char*) malloc(size);
		memcpy(map[file].data, data, size);
	}
}

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}

bool isBinary(std::string in) {
	for(int c: in) {
		if(!std::isalnum(c)) {
			return true;
		}
	}
	return false;
}

std::string parseAddress(const char *file, int inode) {
	std::ifstream in(file);
	if(!in.is_open()) {
		throw std::runtime_error("could not open tcp");
	}
	std::string line;
	while(getline(in, line)) {
		int g, pinode;
		std::string local, remote, unixSocket, gs, pinodes;

		std::istringstream is(line);
		is >> gs >> local >> remote >> gs >> gs >> gs >> pinodes >> unixSocket >> gs >> pinode;

		if(pinode == inode) {
			char buffer[200] = {0};
			int a, b, c, d, port;
			if(sscanf(remote.c_str(), "%2X%2X%2X%2X:%X", &a, &b, &c, &d, &port) == 5) {
				sprintf(buffer, "%d.%d.%d.%d:%d", d, c, b, a, port);
				return std::string(buffer);
			}

			int parts[4];
			if(sscanf(remote.c_str(), "%8X%8X%8X%8X:%X", &parts[0], &parts[1], &parts[2], &parts[3], &port) == 5) {
				for (int i = 0; i < 4; i++) {
					for (int j = 0; j < 4; j++) {
						sprintf(buffer + strlen(buffer), "%02x", (parts[i] >> (8 * j)) & 0xFF);
						if (j == 1 || j == 3) {
							sprintf(buffer + strlen(buffer), ":");
						}
					}
				}

				sprintf(buffer + strlen(buffer), ":%d", port);
				return std::string(buffer);
			}
		}

		if(atoi(pinodes.c_str()) == inode) {
			return std::string(unixSocket);
		}
	}

	return std::string();
}

std::string getAddrWithType(int inode) {
	std::string addr;
	addr = parseAddress("/proc/net/tcp6", inode);
	if(!addr.empty()) {
		return std::string("TCP6: " + addr);
	}

	addr = parseAddress("/proc/net/tcp", inode);
	if(!addr.empty()) {
		return std::string("TCP4: " + addr);
	}

	addr = parseAddress("/proc/net/udp", inode);
	if(!addr.empty()) {
		return std::string("UDP: " + addr);
	}

	addr = parseAddress("/proc/net/unix", inode);
	if(!addr.empty()) {
		return std::string("UNIX: " + addr);
	}

	return addr;
}

void getResourceName(char* result, int pid, int fd) {
	char buffer[128];
	sprintf(buffer, "/proc/%d/fd/%d", pid, fd);
	int l = readlink(buffer, result, 99);
	if(l >= 0) {
		result[l] = 0;
	} else {
		result[0]=0;
	}

	int inode;
	if(sscanf(result, "socket:[%d]", &inode) == 1) {
		std::string addr = getAddrWithType(inode);

		if(!addr.empty()) {
			strcat(result, "\\n");
			strcat(result, addr.c_str());
		}
	}
}

int hook_read(struct tracy_event * e) {
	if (!e->child->pre_syscall) {
		Process &p = get(e->child->pid);

		int len = e->args.return_code;
		if(len <= 0) {
			return TRACY_HOOK_CONTINUE;
		}

		char *data = new char[len+1];
		tracy_read_mem(e->child, data, (tracy_child_addr_t) e->args.a1, len);

		data[len] = 0;

		int fd = e->args.a0;

		char result[100];
		getResourceName(result, e->child->pid, fd);

		if(strncmp(result, "/usr/lib/", strlen("/usr/lib/")) != 0) {
			addFD(p.contents, result, data, len);
		}

		delete[] data;
	}

	return TRACY_HOOK_CONTINUE;
}

int hook_write(struct tracy_event * e) {
    if (e->child->pre_syscall) {
	    Process &p = get(e->child->pid);

	    int len = e->args.a2;
	    char *data = new char[len+1];
	    tracy_read_mem(e->child, data, (tracy_child_addr_t) e->args.a1, len);
	    data[len] = 0;

	    int fd = e->args.a0;


	    char result[100];
		getResourceName(result, e->child->pid, e->args.a0);

	    addFD(p.writes, result, data, len);

	    //fprintf(graph, "%d -> \"%s\" [tooltip=\"%s\", color=blue, penwidth=4];\n", e->child->pid, result/*p.fds[e->args.a0].c_str()*/, data);

	    delete[] data;
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_fork(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		fprintf(graph, "%d [style=filled, fillcolor=yellow];\n", e->args.return_code);
		fprintf(graph, "%d -> %d;\n", e->child->pid, e->args.return_code);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_execve(struct tracy_event *e) {
	if(e->child->pre_syscall) {
		char *path = tracy_read_string(e->child, (tracy_child_addr_t) e->args.a0);

		std::ostringstream os;

		int i = 0;
		while(1) {
			tracy_parent_addr_t argv;
			tracy_read_mem(e->child, &argv, (tracy_child_addr_t) e->args.a1 + 8*i, sizeof(argv));

			if(argv == NULL) {
				break;
			}

			char *c = tracy_read_string(e->child, (tracy_child_addr_t) argv);

			os << c << "\n";

			i++;
		}

		fprintf(graph, "%d [label=\"%s\", style=filled, fillcolor=yellow, target=_blank, URL=\"data:text/plain;base64,%s\",fontsize=12];\n",
		        e->child->pid,
		        path,
		        base64_encode((unsigned char*) os.str().c_str(), os.str().size()).c_str()
		);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_sendmsg(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		Process &p = get(e->child->pid);

		struct msghdr msg;
		tracy_read_mem(e->child, &msg, (tracy_child_addr_t) e->args.a1, sizeof(msg));

		for(int i = 0; i < msg.msg_iovlen; i++) {
			struct iovec first;
			tracy_read_mem(e->child, &first, (tracy_child_addr_t) msg.msg_iov + i * sizeof(first), sizeof(first));

			char *data = new char[first.iov_len];
			tracy_read_mem(e->child, data, (tracy_child_addr_t) first.iov_base, first.iov_len);

			//write(1, data, first.iov_len);
			//printf("\n");


			char result[100];
			getResourceName(result, e->child->pid, e->args.a0);

			if(e->syscall_num == __NR_sendmsg) {
				addFD(p.writes, result, data, first.iov_len);
			} else if(e->syscall_num == __NR_recvmsg) {
				addFD(p.contents, result, data, first.iov_len);
			}

			delete[] data;
		}
	}
	return TRACY_HOOK_CONTINUE;
}


int handle_signal(struct tracy_event *s) {
	printf(">>>%d %d\n", s->child->pid, s->signal_num);

	long wstatus = s->signal_num;

	if (WIFEXITED(wstatus)) {
		printf("exited, status=%d\n", WEXITSTATUS(wstatus));
	} else if (WIFSIGNALED(wstatus)) {
		printf("killed by signal %d\n", WTERMSIG(wstatus));
	} else if (WIFSTOPPED(wstatus)) {
		printf("stopped by signal %d\n", WSTOPSIG(wstatus));
	} else if (WIFCONTINUED(wstatus)) {
		printf("continued\n");
	}



	return TRACY_HOOK_CONTINUE;
}

int mytracy_main(struct tracy *tracy);

int main(int argc, char** argv) {
	char* out = getenv("OUT");
	if(!out) {
		out = "/tmp/graph.dot";
	}

	graph = fopen(out, "w+");
	if(!graph) {
		perror("fopen");
		exit(1);
	}

	std::string ar;
	for(int i = 1; i < argc; i++) {
		ar.append("\\\"");
		ar.append(argv[i]);
		ar.append("\\\" ");
	}

	fprintf(graph, "digraph {label=\"%s\";labelloc=\"t\";\n", ar.c_str());

    struct tracy * tracy;

    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);

	if(tracy_set_signal_hook(tracy, handle_signal) != 0) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

	if (tracy_set_hook(tracy, "read", TRACY_ABI_NATIVE, hook_read)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}
	if (tracy_set_hook(tracy, "recvfrom", TRACY_ABI_NATIVE, hook_read)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

    if (tracy_set_hook(tracy, "write", TRACY_ABI_NATIVE, hook_write)) {
        fprintf(stderr, "Could not hook write\n");
        return EXIT_FAILURE;
    }
	if (tracy_set_hook(tracy, "sendto", TRACY_ABI_NATIVE, hook_write)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}


	if (tracy_set_hook(tracy, "execve", TRACY_ABI_NATIVE, hook_execve)) {
        fprintf(stderr, "Could not hook write\n");
        return EXIT_FAILURE;
    }

	if (tracy_set_hook(tracy, "clone", TRACY_ABI_NATIVE, hook_fork)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

	if (tracy_set_hook(tracy, "sendmsg", TRACY_ABI_NATIVE, hook_sendmsg)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

	if (tracy_set_hook(tracy, "recvmsg", TRACY_ABI_NATIVE, hook_sendmsg)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;

    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec");
        return EXIT_FAILURE;
    }

    mytracy_main(tracy);

    tracy_free(tracy);
	fprintf(graph, "}\n");

    return EXIT_SUCCESS;
}

std::string formatBytes(int i) {
	std::string units[] = {"B", "KB", "MB", "GB", "TB"};
	float bytes = std::max(i, 0);
	float pow = floor((bytes ? log(bytes) : 0) / (float) log(1024));
	pow = std::min((int) pow, (int) (sizeof(units)/sizeof(*units) - 1));

	bytes /= (1 << (10 * (int) pow));

	std::ostringstream os;
	os << std::fixed << std::setprecision(2) << bytes << units[(int) pow];
	return os.str();
}

/* Main function for simple tracy based applications */
int mytracy_main(struct tracy *tracy) {
	struct tracy_event *e;

	/* Setup interrupt handler */
	//main_loop_go_on = 1;
	//signal(SIGINT, _main_interrupt_handler);

	while (1) {
		e = tracy_wait_event(tracy, -1);
		if (!e) {
			fprintf(stderr, "tracy_main: tracy_wait_Event returned NULL\n");
			continue;
		}

		if (e->type == TRACY_EVENT_NONE) {
			break;
		} else if (e->type == TRACY_EVENT_INTERNAL) {
			/*
			printf("Internal event for syscall: %s\n",
					get_syscall_name(e->syscall_num));
			*/
		}
		if (e->type == TRACY_EVENT_SIGNAL) {
			if (TRACY_PRINT_SIGNALS(tracy)) {
				fprintf(stderr, _y("Signal %s (%ld) for child %d")"\n",
				        get_signal_name(e->signal_num), e->signal_num, e->child->pid);
			}
		} else

		if (e->type == TRACY_EVENT_SYSCALL) {
			/*
			if (TRACY_PRINT_SYSCALLS(tracy)) {
				printf(_y("%04d System call: %s (%ld) Pre: %d")"\n",
						e->child->pid, get_syscall_name(e->syscall_num),
						e->syscall_num, e->child->pre_syscall);
			}
			*/
		} else

		if (e->type == TRACY_EVENT_QUIT) {
			if (tracy->opt & TRACY_VERBOSE)
				printf(_b("EVENT_QUIT from %d with signal %s (%ld)\n"),
				       e->child->pid, get_signal_name(e->signal_num),
				       e->signal_num);
			if (e->child->pid == tracy->fpid) {
				if (tracy->opt & TRACY_VERBOSE)
					printf(_g("Our first child died.\n"));
			}

			Process &p = get(e->child->pid);
			for(auto content: p.contents) {
				fprintf(graph, "\"%s\" -> %d [color=red, penwidth=2, target=_blank, URL=\"data:text/plain;base64,%s\", label=\"%s\", fontsize=10];\n",
				        content.first.c_str(),
				        e->child->pid,
				        base64_encode((const unsigned char*) content.second.data, content.second.size).c_str(),
				        formatBytes(content.second.size).c_str()
				);
			}


			for(auto content: p.writes) {
				fprintf(graph, "%d -> \"%s\" [color=blue, penwidth=2, target=_blank, URL=\"data:text/plain;base64,%s\", label=\"%s\", fontsize=10];\n",
				        e->child->pid,
				        content.first.c_str(),
				        base64_encode((const unsigned char*) content.second.data, content.second.size).c_str(),
				        formatBytes(content.second.size).c_str()
				);
			}


			tracy_remove_child(e->child);
			continue;
		}

		if (!tracy_children_count(tracy)) {
			break;
		}

		tracy_continue(e, 0);
	}

	/* Tear down interrupt handler */
	signal(SIGINT, SIG_DFL);

	return 0;
}
