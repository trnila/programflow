#include <stdlib.h>
#include <stdio.h>
#include <unordered_map>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include <cctype>
#include <cstring>
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

		char buffer[128];
		char result[100];
		sprintf(buffer, "/proc/%d/fd/%d", e->child->pid, fd);
		int l = readlink(buffer, result, 99);
		if(l >= 0) {
			result[l] = 0;
		} else {
			result[0]=0;
		}

		addFD(p.contents, result, data, len);

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

	    char buffer[128];
	    char result[100];
	    sprintf(buffer, "/proc/%d/fd/%d", e->child->pid, fd);
	    int l = readlink(buffer, result, 99);
	    result[l] = 0;

	    addFD(p.writes, result, data, len);

	    //fprintf(graph, "%d -> \"%s\" [tooltip=\"%s\", color=blue, penwidth=4];\n", e->child->pid, result/*p.fds[e->args.a0].c_str()*/, data);

	    delete[] data;
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_fork(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		fprintf(graph, "%d -> %d;\n", e->child->pid, e->args.return_code);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_execve(struct tracy_event *e) {
	if(e->child->pre_syscall) {
		char *path = tracy_read_string(e->child, (tracy_child_addr_t) e->args.a0);
		fprintf(graph, "%d [label=\"%s\", style=filled, fillcolor=yellow];\n", e->child->pid, path);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_open(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		Process &p = get(e->child->pid);
		char *path = tracy_read_string(e->child, (tracy_child_addr_t) e->args.a0);

		if(e->args.return_code >= 0) {
			p.fds[e->args.return_code] = path;
		}
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_dup2(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		Process &p = get(e->child->pid);
		p.fds[e->args.a1] = p.fds[e->args.a0];
		//printf("%d -> %d\n", e->args.a0, e->args.a1);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_pipe(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		Process &p = get(e->child->pid);

		int pipes[2];
		tracy_read_mem(e->child, pipes, (tracy_child_addr_t) e->args.a0, sizeof(pipes));

		p.fds[pipes[0]] = "pipe";
		p.fds[pipes[1]] = "pipe";

		for(int i = 0; i < 10; i++) {
			printf(">%d - %s\n", i, p.fds[i].c_str());
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
	graph = fopen("/tmp/graph.dot", "w+");
	fprintf(graph, "digraph {sep=\"+25,25\";overlap=scalexy;node [fontsize=11];splines=true;\n");

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

    if (tracy_set_hook(tracy, "write", TRACY_ABI_NATIVE, hook_write)) {
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

	/*if (tracy_set_hook(tracy, "open", TRACY_ABI_NATIVE, hook_open)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

	if (tracy_set_hook(tracy, "dup2", TRACY_ABI_NATIVE, hook_dup2)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}

	if (tracy_set_hook(tracy, "pipe", TRACY_ABI_NATIVE, hook_pipe)) {
		fprintf(stderr, "Could not hook write\n");
		return EXIT_FAILURE;
	}*/

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
				fprintf(graph, "\"%s\" -> %d [color=red, penwidth=2, target=_blank, URL=\"data:text/plain;base64,%s\"];\n",
				        content.first.c_str(),
				        e->child->pid,
				        base64_encode((const unsigned char*) content.second.data, content.second.size).c_str()
				);
			}


			for(auto content: p.writes) {
				fprintf(graph, "%d -> \"%s\" [color=blue, penwidth=2, target=_blank, URL=\"data:text/plain;base64,%s\"];\n",
				        e->child->pid,
				        content.first.c_str(),
				        base64_encode((const unsigned char*) content.second.data, content.second.size).c_str()
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
