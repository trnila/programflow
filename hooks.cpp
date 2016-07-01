#include <sstream>
#include <syscall.h>
#include <sys/socket.h>
#include "processes.h"
#include "utils.h"

extern "C" {
#include "tracy/src/tracy.h"
}

int hook_read(struct tracy_event * e) {
	if (!e->child->pre_syscall) {
		Process &p = getProcess(e->child->pid);

		int len = e->args.return_code;
		if(len <= 0) {
			return TRACY_HOOK_CONTINUE;
		}

		char *data = new char[len+1];
		tracy_read_mem(e->child, data, (tracy_child_addr_t) e->args.a1, len);

		data[len] = 0;

		int fd = e->args.a0;
		addContentToFD(e->child->pid, fd, data, len, 0);

		delete[] data;
	}

	return TRACY_HOOK_CONTINUE;
}

int hook_write(struct tracy_event * e) {
	if (e->child->pre_syscall) {
		Process &p = getProcess(e->child->pid);

		int len = e->args.a2;
		char *data = new char[len+1];
		tracy_read_mem(e->child, data, (tracy_child_addr_t) e->args.a1, len);
		data[len] = 0;

		int fd = e->args.a0;

		addContentToFD(e->child->pid, fd, data, len, 1);

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

			os << c << " ";

			i++;
		}

		fprintf(graph, "%d [label=\"%s\", style=filled, fillcolor=yellow, target=_blank, URL=\"data:text/plain,%s\",fontsize=12];\n",
		        e->child->pid,
		        path,
		        xmlentities(os.str()).c_str()
		);
	}
	return TRACY_HOOK_CONTINUE;
}

int hook_sendmsg(struct tracy_event *e) {
	if(!e->child->pre_syscall) {
		Process &p = getProcess(e->child->pid);

		struct msghdr msg;
		tracy_read_mem(e->child, &msg, (tracy_child_addr_t) e->args.a1, sizeof(msg));

		for(int i = 0; i < msg.msg_iovlen; i++) {
			struct iovec first;
			tracy_read_mem(e->child, &first, (tracy_child_addr_t) msg.msg_iov + i * sizeof(first), sizeof(first));

			char *data = new char[first.iov_len];
			tracy_read_mem(e->child, data, (tracy_child_addr_t) first.iov_base, first.iov_len);

			//write(1, data, first.iov_len);
			//printf("\n");


			int fd = e->args.a0;

			if(e->syscall_num == __NR_sendmsg) {
				addContentToFD(e->child->pid, fd, data, first.iov_len, 1);
			} else if(e->syscall_num == __NR_recvmsg) {
				addContentToFD(e->child->pid, fd, data, first.iov_len, 0);
			}

			delete[] data;
		}
	}
	return TRACY_HOOK_CONTINUE;
}
