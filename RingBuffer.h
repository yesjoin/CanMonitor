#pragma once
#include <mutex>

template <typename T>
class RingBuffer {
public:
    explicit RingBuffer(size_t capacity) : m_capacity(capacity + 1), m_head(0), m_tail(0) {
        m_data = new T[m_capacity]; // 彻底抛弃 vector，用原生指针分配内存
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
    std::mutex m_mtx;  
};

// 模板类实现必须放在头文件里
template <typename T>
bool RingBuffer<T>::push(const T& item) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if ((m_head + 1) % m_capacity == m_tail) {
        m_tail = (m_tail + 1) % m_capacity; 
    }
    m_data[m_head] = item;
    m_head = (m_head + 1) % m_capacity; 
    return true;
}

template <typename T>
bool RingBuffer<T>::pop(T& item) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_head == m_tail) {
        return false; 
    }
    item = m_data[m_tail];
    m_tail = (m_tail + 1) % m_capacity; 
    return true;
}