#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include "CanFrame.h"
#include "RingBuffer.h"

using namespace std;

// 全局共享资源
RingBuffer<struct can_frame> frameQueue(100); 
bool isRunning = true; 

// 线程 A：专门负责收报文
void receiveThread(int s) {
    struct can_frame frame;
    while (isRunning) {
        int nbytes = read(s, &frame, sizeof(struct can_frame));
        if (nbytes > 0) {
            frameQueue.push(frame);
        }
    }
}

// 线程 B：专门负责处理和安全检测
void processThread() {
    while (isRunning) {
        struct can_frame frame;
        
        // 从环形队列拿数据，拿到了返回 true
        if (frameQueue.pop(frame)) {
            CanFrame myFrame(frame.can_id, frame.can_dlc, frame.data);

            if (!myFrame.isValid()) {
                cout << "[WARN] 捕获到非法畸形报文，长度不匹配！" << endl;
            } 
            else if (myFrame.id == 0x3C0) {
                cout << "[ERROR] 发现黑名单报文 0x3C0,已触发安全拦截！" << endl;
            }
            else if (myFrame.id == 0x7E0 && myFrame.dlc >= 2 && myFrame.data[1] == 0x27) {
                cout << "🚨 [严重告警] 捕获到 UDS 27 安全访问爆破尝试！" << endl;
            }
            else {
                cout << "[INFO] 收到正常 CAN 帧 ID: 0x" << hex << myFrame.id << dec << endl;
            }
        } 
        else {
            // 没数据时休眠
            this_thread::sleep_for(chrono::milliseconds(10));
        }
    }
}

int main() {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("Socket 创建失败"); return 1; }
    
    struct ifreq ifr;
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);
    
    struct sockaddr_can addr;
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("Bind 失败"); return 1; }

    cout << "=== 多线程 CanMonitor (RingBuffer版) 已启动 ===" << endl;

    thread t1(receiveThread, s);
    thread t2(processThread);

    t1.join();
    t2.join();

    return 0;
}