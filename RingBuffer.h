#pragma once
#include <mutex>

template <typename T>
class RingBuffer {
public:
    //注意：传入的 capacity 必须是 2 的幂次方
    explicit RingBuffer(size_t capacity) : 
        m_capacity(capacity),
        m_head(0),
        m_tail(0),
        m_count(0) //初始化计数器
    {
        m_data = new T[m_capacity];
    }

    ~RingBuffer() {
        delete[] m_data; // 释放内存
    }

    bool push(const T& item);
    bool pop(T& item);

private:
    T* m_data;         // 原生数组指针
    size_t m_capacity; 
    size_t m_head;     
    size_t m_tail;  
    size_t m_count;   
    std::mutex m_mtx;  
};

// 模板类实现必须放在头文件里
template <typename T>
bool RingBuffer<T>::push(const T& item) {
    std::lock_guard<std::mutex> lock(m_mtx);

    m_data[m_head] = item;

    // 👈 魔法操作：位运算，等效于 (m_head + 1) % m_capacity，但速度极快！
    m_head = (m_head + 1) & (m_capacity - 1);

    //如果满了覆盖最老的数据 （移动 tail 指针）
    if (m_count == m_capacity) {

        m_tail = (m_head + 1) & (m_capacity - 1);
    } else {
        m_count++;
    }
    return true;
}

template <typename T>
bool RingBuffer<T>::pop(T& item) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_count == 0) {
        return false; //队列空了
    }
    item = m_data[m_tail];

    m_tail = (m_tail + 1) & (m_capacity - 1);
    m_count--;
    
    
    return true;
}