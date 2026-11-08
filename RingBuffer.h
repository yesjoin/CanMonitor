#pragma once
// ============================================================================
// RingBuffer.h —— 有界阻塞队列（单生产者 / 单消费者）
//
//   1. 容量 N 为编译期常量且必须是 2 的幂，用 &(N-1) 代替 %N，
//      避免在临界区里发 divq（32~42 cycle，不可流水化）。
//   2. 用 m_size 显式记录元素个数，full/empty 不会混淆，N 个槽位全部可用。
//   3. push 为万能引用：左值拷贝、右值移动。
//   4. 满时覆盖最旧元素并返回 false —— 丢帧必须让调用方看见。
//   5. popBatch 一次搬走最多 maxCount 个，锁代价摊薄；空队列时条件变量挂起。
//
// 约束：单生产者 + 单消费者。生产者永不阻塞。
// ============================================================================

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <type_traits>
#include <utility>

template <typename T, std::size_t N>
class RingBuffer {
    static_assert(N >= 2,             "RingBuffer 容量至少为 2");
    static_assert((N & (N - 1)) == 0, "RingBuffer 容量必须是 2 的幂");

public:
    inline static constexpr std::size_t kCapacity      = N;
    inline static constexpr int         kWaitTimeoutMs = 50;

    RingBuffer() = default;

    RingBuffer(const RingBuffer&)            = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;
    RingBuffer(RingBuffer&&)                 = delete;
    RingBuffer& operator=(RingBuffer&&)      = delete;

    // 返回 false 表示队列已满、最旧元素被覆盖丢弃。
    template <typename U>
    bool push(U&& item) {
        static_assert(std::is_assignable<T&, U&&>::value,
                      "RingBuffer<T>::push 要求 T 可由 U&& 赋值");

        bool dropped = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_size == N) {
                m_tail = (m_tail + 1) & (N - 1);
                dropped = true;
            } else {
                ++m_size;
            }
            m_data[m_head] = std::forward<U>(item);
            m_head = (m_head + 1) & (N - 1);
        }
        m_cv.notify_one();
        return !dropped;
    }

    // 返回实际搬走的个数；0 表示等待 kWaitTimeoutMs 后仍无数据。
    std::size_t popBatch(T* out, std::size_t maxCount) {
        if (maxCount == 0 || out == nullptr) return 0;

        std::unique_lock<std::mutex> lk(m_mtx);
        if (m_size == 0) {
            m_cv.wait_for(lk, std::chrono::milliseconds(kWaitTimeoutMs),
                          [this] { return m_size != 0; });
            if (m_size == 0) return 0;
        }

        const std::size_t n = std::min(maxCount, m_size);
        for (std::size_t i = 0; i < n; ++i) {
            out[i] = std::move(m_data[m_tail]);
            m_tail = (m_tail + 1) & (N - 1);
        }
        m_size -= n;
        return n;
    }

    bool pop(T& item) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_size == 0) return false;
        item = std::move(m_data[m_tail]);
        m_tail = (m_tail + 1) & (N - 1);
        --m_size;
        return true;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_size;
    }
    bool empty() const { return size() == 0; }
    bool full()  const { return size() == N; }

private:
    alignas(64) T m_data[N];

    std::size_t m_head = 0;
    std::size_t m_tail = 0;
    std::size_t m_size = 0;

    mutable std::mutex      m_mtx;
    std::condition_variable m_cv;
};
