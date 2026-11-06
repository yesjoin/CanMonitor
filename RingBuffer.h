#pragma once
// ============================================================================
// RingBuffer.h —— 方案 A：互斥锁 + 条件变量 + 批量拉取
//
// 相对上一版的关键改动：
//   1. 容量 N 改成编译期模板参数，且强制 2 的幂 —— 用 &(N-1) 代替 %N，
//      把临界区里 4 条 divq（每条 32~42 cycle）换成 4 条 and（每条 1 cycle）。
//   2. 用 m_size 显式记录元素个数，full/empty 不会混淆，N 个槽位全部可用。
//   3. push 改成万能引用：左值拷贝、右值移动。对 std::string/vector 载荷
//      能省掉一次堆分配；对 can_frame 这种 16B POD 则完全等价。
//   4. 满时覆盖最旧元素，并返回 false —— 丢帧必须让调用方看见，绝不静默。
//   5. 新增 popBatch()：一次最多搬走 maxCount 帧，锁的代价被摊薄 maxCount 倍。
//   6. 队列为空时在条件变量上真正挂起，不再需要上层 sleep 轮询。
//
// 约束：
//   · 单生产者 + 单消费者（与 CAN 收报/处理双线程模型一致）
//   · 生产者永不阻塞：push 不等待、不睡眠，满了立刻返回 false
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
    static_assert(N >= 2,               "RingBuffer 容量至少为 2");
    static_assert((N & (N - 1)) == 0,   "RingBuffer 容量必须是 2 的幂，否则 &(N-1) 取模不成立");

public:
    static constexpr std::size_t kCapacity      = N;
    inline static constexpr int         kWaitTimeoutMs = 50;   // popBatch 空等上限

    RingBuffer() = default;

    // 内含 std::mutex 与 std::condition_variable，二者均不可拷贝/移动，
    // 这里显式 delete，把"不可拷贝"从隐式行为变成接口契约。
    RingBuffer(const RingBuffer&)            = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;
    RingBuffer(RingBuffer&&)                 = delete;
    RingBuffer& operator=(RingBuffer&&)      = delete;

    // ------------------------------------------------------------------
    // push：生产者调用
    //
    //   返回 true  —— 正常入队
    //   返回 false —— 队列已满，最旧的一帧被覆盖丢弃（调用方必须计数）
    //
    // 锁内只做两件事：16 B 搬运 + 索引推进。没有任何可能阻塞/分配的操作。
    // notify_one 放在解锁之后：避免被唤醒的消费者立刻又卡在 mutex 上
    // （也就是所谓的 "hurry up and wait"）。
    // ------------------------------------------------------------------
    template <typename U>
    bool push(U&& item) {
        static_assert(std::is_assignable<T&, U&&>::value,
                      "RingBuffer<T>::push 要求 T 可由 U&& 赋值");

        bool dropped = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);

            if (m_size == N) {
                // 满：丢弃最旧的一帧，tail 前移一槽，size 不变
                m_tail = (m_tail + 1) & (N - 1);
                dropped = true;
            } else {
                ++m_size;
            }

            m_data[m_head] = std::forward<U>(item);   // 左值拷贝 / 右值移动
            m_head = (m_head + 1) & (N - 1);          // 位运算取模，1 cycle
        }

        m_cv.notify_one();        // 无等待者时仅是一次原子读 + 分支，约 2~5 ns
        return !dropped;
    }

    // ------------------------------------------------------------------
    // popBatch：消费者调用
    //
    //   out      调用方提供的缓冲区，容量至少为 maxCount 个 T
    //   maxCount 本次最多搬走多少帧
    //   返回     实际搬走的帧数；0 表示等待 kWaitTimeoutMs 后仍无数据
    //
    // 关键点：
    //   · 只有队列为空时才进入 wait_for；有数据立即返回，不做多余的系统调用。
    //   · wait_for 带谓词，天然免疫虚假唤醒（spurious wakeup）。
    //   · 本函数返回后锁已释放，调用方的业务处理、日志、I/O 全部在锁外。
    // ------------------------------------------------------------------
    std::size_t popBatch(T* out, std::size_t maxCount) {
        if (maxCount == 0 || out == nullptr) return 0;

        std::unique_lock<std::mutex> lk(m_mtx);

        if (m_size == 0) {
            // 线程在此进入睡眠态（内核 TASK_INTERRUPTIBLE），不占 CPU 时间片。
            // 被 notify_one 唤醒、或超时 50 ms 后返回，回到循环顶部检查退出标志。
            m_cv.wait_for(lk,
                          std::chrono::milliseconds(kWaitTimeoutMs),
                          [this] { return m_size != 0; });

            if (m_size == 0) return 0;      // 超时且仍为空
        }

        const std::size_t n = std::min(maxCount, m_size);

        for (std::size_t i = 0; i < n; ++i) {
            out[i] = std::move(m_data[m_tail]);   // 非平凡 T 省一次拷贝
            m_tail = (m_tail + 1) & (N - 1);
        }
        m_size -= n;

        return n;
    }

    // ------------------------------------------------------------------
    // pop：单帧版本，保留给不关心吞吐的调用点
    // ------------------------------------------------------------------
    bool pop(T& item) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_size == 0) return false;

        item = std::move(m_data[m_tail]);
        m_tail = (m_tail + 1) & (N - 1);
        --m_size;
        return true;
    }

    // ---- 观测接口：会抢锁，不要放进热路径 -----------------------------
    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_size;
    }
    bool empty() const { return size() == 0; }
    bool full()  const { return size() == N; }

private:
    // 数据区放在最前面并 64 字节对齐：16 B 的 can_frame 正好 4 帧一行，
    // 不会出现单帧跨两条 cache line。
    // 注意：这会让整个类型 over-aligned —— 作为全局/静态对象没问题，
    // 若将来要 new 出来，C++17 起编译器才保证 over-aligned 分配。
    alignas(64) T m_data[N];

    std::size_t m_head = 0;   // 下一个写入位置 [0, N)
    std::size_t m_tail = 0;   // 下一个读出位置 [0, N)
    std::size_t m_size = 0;   // 当前元素个数 [0, N]

    mutable std::mutex      m_mtx;
    std::condition_variable m_cv;
};