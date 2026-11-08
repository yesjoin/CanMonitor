cmake_minimum_required(VERSION 3.10)
project(CanSentinel)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 告诉编译器去 include 文件夹里找头文件
include_directories(include)

# 寻找多线程库
find_package(Threads REQUIRED)

# ==========================================
# 1. 编译底层网关 (can-gateway)
# ==========================================
add_executable(can-gateway 
    src/can-gateway.cpp 
    src/CanFrame.cpp
    # 如果 RingBuffer.cpp 已经删了（代码全在头文件里），就不需要加
)
# 链接多线程库
target_link_libraries(can-gateway Threads::Threads)

# ==========================================
# 2. 编译 AI 代理 (alert-agent)
# ==========================================
add_executable(alert-agent 
    src/alert-agent.cpp
)
target_link_libraries(alert-agent Threads::Threads)