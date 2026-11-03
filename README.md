# 车载 CAN 总线安全监控网关 (Linux C++)

## 📌 项目简介
这是一个基于 Linux 环境开发的轻量级车载 CAN 总线安全监控网关。项目采用 C++11 多线程架构，直接与底层 SocketCAN 接口交互，具备实时报文解析、异常报文检测以及针对 UDS 诊断协议（0x27 服务）的暴力破解告警能力。

## 🛠️ 技术栈
- **开发语言**：C++11, Python3
- **底层通信**：Linux SocketCAN (`<linux/can.h>`)
- **并发模型**：`std::thread` 生产者-消费者模型，使用 `std::mutex` 保证线程安全
- **构建工具**：CMake

## ⚙️ 核心架构
1. **接收线程 (Receiver Thread)**：阻塞读取 `vcan0` 虚拟总线数据，负责将底层裸报文存入共享队列。
2. **处理线程 (Process Thread)**：从队列中取出报文，执行安全规则校验，利用 `sleep_for` 防止 CPU 空转。
3. **安全防御逻辑**：
   - **畸形报文检测**：校验 DLC 声明长度与实际数据长度是否一致。
   - **黑名单拦截**：实时拦截指定的恶意控制 ID（如 0x3C0）。
   - **UDS 安全爆破监控**：拦截发往 `0x7E0` 且包含 `0x27`（Security Access）服务的非法诊断请求。

## 🚀 编译与运行

### 编译
```bash
mkdir build && cd build
cmake ..
make