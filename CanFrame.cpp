#include "CanFrame.h"

CanFrame::CanFrame(unsigned int i, unsigned char d, const unsigned char* dat) : id(i), dlc(d) {
    // 把传入的底层数据拷贝到我们的固定数组中
    for (int k = 0; k < dlc && k < 8; k++) {
        data[k] = dat[k];
    }
}

bool CanFrame::isValid() const {
    if (dlc > 8) return false; 
    return true;
}