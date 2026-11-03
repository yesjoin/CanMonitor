#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include "CanFrame.h"

using namespace std;

// 全局共享资源
queue<struct can_frame> frameQueue; // 共享仓库
mutex mtx;                          // 互斥锁
bool isRunning = true;              // 运行标志

// 线程 A：专门负责收报文
void receiveThread(int s) {
    struct can_frame frame;
    while (isRunning) {
        int nbytes = read(s, &frame, sizeof(struct can_frame));
        if (nbytes > 0) {
            lock_guard<mutex> lock(mtx); // 上锁
            frameQueue.push(frame);
        }
    }
}

// 线程 B：专门负责处理和安全检测
void processThread() {
    while (isRunning) {
        struct can_frame frame;
        bool hasData = false;

        // 尝试拿钥匙，从仓库拿数据
        {
            lock_guard<mutex> lock(mtx); // 上锁
            if (!frameQueue.empty()) {
                frame = frameQueue.front();
                frameQueue.pop();
                hasData = true;
            }
        } // 离开这个区域，锁自动解开！

        // 处理业务逻辑（不要在锁的范围内做耗时的打印）
        if (hasData) {
            // 将底层 C 结构体转换为 C++ 类
            CanFrame myFrame(frame.can_id, frame.can_dlc, frame.data);

            if (!myFrame.isValid()) {
                cout << "[WARN] 捕获到非法畸形报文，长度不匹配！" << endl;
            } 
            else if (myFrame.id == 0x3C0) {
                cout << "[ERROR] 发现黑名单报文 0x3C0,已触发安全拦截！" << endl;
            } 
            //新增：UDS安全访问（0x27服务）爆破监控
            else if (myFrame.id == 0x7E0 && myFrame.dlc >= 2 && myFrame.data[1] == 0x27) {
                cout << "[严重警告]捕获到UDS安全访问爆破尝试!" << endl;    
            }   
            else {
                cout << "[INFO] 收到正常 CAN 帧 ID: 0x" << hex << myFrame.id << dec << endl;
            }
        } else {
            // 如果没收到数据，稍微睡一下，把 CPU 让给别人
            this_thread::sleep_for(chrono::milliseconds(1000));
            cout << "[心跳]系统运行正常,当前无报文..." << endl;
        }
    }
}

int main() {
    // 初始化 Socket 绑定 vcan0
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("Socket 创建失败"); return 1; }
    
    struct ifreq ifr;
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);
    
    struct sockaddr_can addr;
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { 
        perror("Bind 失败"); 
        return 1; 
    }

    cout << "=== 多线程 CanMonitor 工业网关已启动 ===" << endl;

    // 启动两个线程
    thread t1(receiveThread, s);
    thread t2(processThread);

    // 让主线程等在这里
    t1.join();
    t2.join();

    return 0;
}