#include <iomanip>
#include <sstream>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>

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

void ensureDirectoryExists(std::string dir) {
	std::string::size_type last = 1;
	std::string::size_type pos;

	do {
		pos = dir.find('/', last);

		//std::cout << dir.substr(0, pos) << "\n";
		if(mkdir(dir.substr(0, pos).c_str(), 0700) != 0) {
			if(errno != EEXIST) {
				perror("Could not create directory");
				exit(1);
			}
		}

		last = pos + 1;
	} while (pos != std::string::npos);
}
