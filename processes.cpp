#include <signal.h>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include "processes.h"
#include "utils.h"

char *directory = "";
FILE* graph;

File getFDName(int pid, int fd);

std::unordered_map<pid_t, Process> processes;

Process& getProcess(pid_t pid) {
	auto it = processes.find(pid);
	if(it != processes.end()) {
		return it->second;
	}

	processes[pid] = Process();
	return processes[pid];
}

void deleteProcess(pid_t pid) {
	processes.erase(pid);
}

void addContentToFD(pid_t pid, int fd, char *data, size_t size, bool write) {
	Process &process = getProcess(pid);

	auto &map = write ? process.writes : process.reads;


	File f = getFDName(pid, fd);
	std::string lib = "/usr/lib";
	if(f.getUniqueIdentifier().substr(0, lib.size()) == lib) {
		return;
	}

	auto it = map.find(f.getUniqueIdentifier());
	if(it == map.end()) {
		auto fix = [](std::string str) -> std::string {
			for(char &c: str) {
				if(c == '/' || c == '\\') {
					c = '-';
				}
			}

			return str.at(0) == '-' ? str.substr(1) : str;
		};

		std::string filename = fix(f.getUniqueIdentifier()) + (write ? ".out" : ".in");
		std::string relative = std::to_string(pid) + "/" + filename;
		std::string absolute = std::string(directory) + "/" + std::to_string(pid) + "/";
		ensureDirectoryExists(absolute);
		absolute += filename;

		it = map.emplace(f.getUniqueIdentifier(), FDContent(absolute.c_str(), relative.c_str(), f)).first;
	}

	it->second.write(data, size);
}

std::string getInodeDescription(const char *file, int inode) {
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
	addr = getInodeDescription("/proc/net/tcp6", inode);
	if(!addr.empty()) {
		return std::string("TCP6: " + addr);
	}

	addr = getInodeDescription("/proc/net/tcp", inode);
	if(!addr.empty()) {
		return std::string("TCP4: " + addr);
	}

	addr = getInodeDescription("/proc/net/udp", inode);
	if(!addr.empty()) {
		return std::string("UDP: " + addr);
	}

	addr = getInodeDescription("/proc/net/unix", inode);
	if(!addr.empty()) {
		return std::string("UNIX: " + addr);
	}

	return addr;
}

File getFDName(int pid, int fd) {
	char buffer[128];
	char result[1000];
	sprintf(buffer, "/proc/%d/fd/%d", pid, fd);
	int l = readlink(buffer, result, 99);
	if(l >= 0) {
		result[l] = 0;
	} else {
		result[0]=0;
	}

	std::ostringstream label;
	label << result;

	int inode;
	if(sscanf(result, "socket:[%d]", &inode) == 1) {
		std::string addr = getAddrWithType(inode);

		if(!addr.empty()) {
			label << "\n" << addr.c_str();
		}
	}

	return File(result, label.str());
}
