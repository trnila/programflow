#pragma once

#include <unordered_map>
#include <fstream>

extern char *directory;//TODO: fix thi!
extern FILE* graph;

class File {
public:
	File(const std::string &uniqueId, const std::string &label) : uniqueId(uniqueId), label(label){}

	std::string getUniqueIdentifier() {
		return uniqueId;
	}

	std::string getLabel() {
		return label;
	}

private:
	std::string uniqueId;
	std::string label;
};

class FDContent {
public:
	FDContent(const char *name, File file): out(name), fileName(name), file(file) {
		out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		if(!out.is_open()) {
			perror("failed to open file!");
		}
	}

	void write(const char* data, size_t size) {
		out.write(data, size);
		out.flush();
		total += size;
	}

	const std::string& getOutputFileName() {
		return fileName;
	}

	size_t getSize() {
		return total;
	}

	File getFile() {
		return file;
	}


private:
	std::ofstream out;
	size_t total = 0;
	std::string fileName;
	File file;
};

typedef struct _Process {
	std::unordered_map<std::string, FDContent> reads;
	std::unordered_map<std::string, FDContent> writes;
} Process;

Process& getProcess(pid_t pid);

void addContentToFD(pid_t pid, int fd, char *data, size_t size, bool write);