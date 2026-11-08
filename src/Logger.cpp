#include "logger.h"
#include <ctime>

//获取当前时间
std::string getTime() {
    time_t now = time(0);
    char* dt = ctime(&now);
    std::string s(dt);
    s.pop_back(); //去掉换行符
    return s;
}

void Logger::info(const std::string& msg) {
    std::cout << "[" << getTime() << "] [INFO] " << msg << std::endl;
}
void Logger::warn(const std::string& msg) {
    std::cout << "[" << getTime() << "] [WARN] " << msg << std::endl;
}
void Logger::error(const std::string& msg) {
    std::cout << "[" << getTime() << "] [ERROR] " << msg << std::endl;
}