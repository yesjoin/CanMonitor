#pragma once

class CanFrame {
public:
    unsigned int id;
    unsigned char dlc;
    unsigned char data[8]; // 👈 最长只有 8 字节，直接开个 8 的数组

    CanFrame(unsigned int i, unsigned char d, const unsigned char* dat);
    bool isValid() const; 
};