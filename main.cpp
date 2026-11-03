#include <iostream>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include "CanFrame.h"

using namespace std;

int main() {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { cout << "Socket 创建失败" << endl; return 1; }
    
    struct ifreq ifr;
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);
    
    struct sockaddr_can addr;
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(s, (struct sockaddr *)&addr, sizeof(addr));

    cout << "[INFO] CanMonitor 网关已启动，正在监听 vcan0..." << endl;

    struct can_frame frame;
    while (true) {
        int nbytes = read(s, &frame, sizeof(struct can_frame));
        if (nbytes > 0) {
            // 👈 这里直接把底层数组扔进去，不用再折腾 vector 了
            CanFrame myFrame(frame.can_id, frame.can_dlc, frame.data);

            if (!myFrame.isValid()) {
                cout << "[WARN] 捕获到非法畸形报文，长度不匹配！" << endl;
            } 
            else if (myFrame.id == 0x3C0) {
                cout << "[ERROR] 发现黑名单报文 0x3C0，已触发安全拦截！" << endl;
            } 
            else {
                cout << "[INFO] 收到正常 CAN 帧 ID: 0x" << hex << myFrame.id << dec << endl;
            }
        }
    }
    return 0;
}