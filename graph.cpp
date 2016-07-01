#include <stdlib.h>
#include <stdio.h>
#include <unordered_map>
#include <cstring>
#include <sstream>
#include <math.h>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <functional>
#include "utils.h"
#include "hooks.h"
#include "processes.h"

extern "C" {
	#include "tracy/src/tracy.h"
}


int mytracy_main(struct tracy *tracy);



int main(int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: %s <outputDirectory> <program-name> <args...>\n", argv[0]);
		return -1;
	}

	directory = argv[1];
	ensureDirectoryExists(directory);

	graph = fopen((std::string(directory) + "/graph").c_str(), "w+");
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

	const std::unordered_map<const char*, int(*)(struct tracy_event*)> hooks {
			{"read", hook_read},
			{"recvfrom", hook_read},
			{"write", hook_write},
			{"sendto", hook_write},
			{"execve", hook_execve},
			{"clone", hook_fork},
			{"sendmsg", hook_sendmsg},
			{"recvmsg", hook_sendmsg}
	};

	for(auto &pair: hooks) {
		if(tracy_set_hook(tracy, (char*) pair.first, TRACY_ABI_NATIVE, pair.second)) {
			fprintf(stderr, "Could not hook %s", "a");
			return -1;
		}
	}

    argv++; argc--;

    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec");
        return -1;
    }

    mytracy_main(tracy);

    tracy_free(tracy);
	fprintf(graph, "}\n");

    return -1;
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

			Process &p = getProcess(e->child->pid);
			for(auto &content: p.reads) {
				fprintf(graph, "\"%s\" -> %d [color=red, penwidth=2, target=_blank, URL=\"%s\", label=\"%s\", fontsize=10];\n",
				        content.second.getFile().getLabel().c_str(),
				        e->child->pid,
				        content.second.getOutputFileName().c_str(),
				        formatBytes(content.second.getSize()).c_str()
				);
			}


			for(auto &content: p.writes) {
				fprintf(graph, "%d -> \"%s\" [color=blue, penwidth=2, target=_blank, URL=\"%s\", label=\"%s\", fontsize=10];\n",
				        e->child->pid,
				        content.second.getFile().getLabel().c_str(),
				        content.second.getOutputFileName().c_str(),
				        formatBytes(content.second.getSize()).c_str()
				);
			}

			deleteProcess(e->child->pid);

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
