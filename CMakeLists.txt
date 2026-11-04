cmake_minimum_required(VERSION 3.10)
project(CanMonitor)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 寻找多线程库 (pthread)
find_package(Threads REQUIRED)

# 👇 关键！必须先用 add_executable 告诉 CMake 我们要编译生成 CanMonitor 这个程序
# 注意：这里去掉了 RingBuffer.cpp，因为代码全写在 RingBuffer.h 里了
add_executable(CanMonitor main_thread.cpp CanFrame.cpp)

# 👇 然后才能给这个程序链接多线程库
target_link_libraries(CanMonitor Threads::Threads)