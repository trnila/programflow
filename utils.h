#pragma once
#include <string>

std::string formatBytes(int i);
void ensureDirectoryExists(std::string dir);
std::string escape(const std::string &str);
std::string xmlentities(const std::string &str);