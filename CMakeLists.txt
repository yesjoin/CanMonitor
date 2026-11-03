cmake_minimum_required(VERSION 3.10)
project(CanMonitor)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 👇 新增：寻找系统的多线程库 (pthread)
find_package(Threads REQUIRED)

# 👇 注意这里改成了 main_thread.cpp
add_executable(CanMonitor main_thread.cpp CanFrame.cpp)

# 👇 新增：把多线程库链接到你的程序上
target_link_libraries(CanMonitor Threads::Threads)