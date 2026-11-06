// ============================================================================
// main_thread.cpp —— CAN 监控网关（方案 A：条件变量 + 批量拉取）
//
// 线程模型：
//   receiveThread —— poll + read，push 入队，永不阻塞
//   processThread —— popBatch 批量取帧，锁外做检测与统计
// ============================================================================
#include <string>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "CanFrame.h"
#include "RingBuffer.h"

namespace {

// ---- 全局共享状态 ----------------------------------------------------------

// 队列容量从运行期参数改成模板参数，必须是 2 的幂。
// 4096 帧 × 16 B = 64 KB，10k fps 下约 400 ms 的缓冲深度，
// 足以吸收调度抖动、终端写阻塞、页回收这类瞬时停顿。
RingBuffer<can_frame, 4096> g_queue;

std::atomic<bool>          g_running{true};
std::atomic<std::uint64_t> g_dropped{0};       // 队列溢出丢弃数
std::atomic<std::uint64_t> g_normal{0};        // 正常帧数
std::atomic<std::uint64_t> g_bad{0};           // 畸形帧数
std::atomic<std::uint64_t> g_blacklisted{0};   // 黑名单命中数
std::atomic<std::uint64_t> g_bruteforce{0};    // UDS 27 爆破数

void onSignal(int) { g_running.store(false, std::memory_order_relaxed); }

// 告警限流器：同一类告警 200 ms 内最多打印一次。
// 不加这个，攻击者用 10k fps 的 0x3C0 洪泛就能把 std::cout 变成 DoS 放大器——
// 每帧一次终端 write（10~100 µs），CPU 先被打满，检测逻辑反而最先崩掉。
struct AlertLimiter {
    using clock = std::chrono::steady_clock;
    clock::time_point last{};

    bool allow(std::chrono::milliseconds gap = std::chrono::milliseconds(200)) {
        const auto now = clock::now();
        if (now - last < gap) return false;
        last = now;
        return true;
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// 接收线程：只做一件事 —— 尽可能快地把 CAN 帧塞进队列
//
// 这个线程绝对不能阻塞在业务逻辑或日志上。一旦它停下来，内核 socket
// 接收队列（SO_RCVBUF）填满，后续帧会在 raw_rcv() 里被静默丢弃，
// 连用户态的计数器都看不到——那比在你自己队列里丢帧严重得多。
// ---------------------------------------------------------------------------
void receiveThread(int s) {
    can_frame frame{};

    pollfd pfd{};
    pfd.fd     = s;
    pfd.events = POLLIN;

    while (g_running.load(std::memory_order_relaxed)) {
        // 100 ms 超时：让线程能周期性检查退出标志，而不是永远卡在 read()
        const int rc = ::poll(&pfd, 1, 100);
        if (rc < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            g_running.store(false);
            break;
        }
        if (rc == 0) continue;                    // 超时，无数据
        if ((pfd.revents & POLLIN) == 0) {        // POLLERR / POLLHUP：接口 down
            g_running.store(false);
            break;
        }

        const ssize_t n = ::read(s, &frame, sizeof(frame));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            std::perror("read");
            g_running.store(false);
            break;
        }
        if (n != static_cast<ssize_t>(sizeof(frame))) continue;   // 短读/尺寸异常

        // push 不阻塞、不等待：满了就覆盖最旧并返回 false
        if (!g_queue.push(frame)) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }
}
// 🟢 复制区：调用本地 Ollama 的 AI 函数
std::string ask_ai(const std::string& prompt) {
    // 构造 JSON 请求体
    std::string json_body = "{\"model\":\"qwen2:0.5b\",\"prompt\":\"" + prompt + "\",\"stream\":false}";
    
    // 构造 curl 命令
    std::string cmd = "curl -s http://localhost:11434/api/generate -d '" + json_body + "'";
    
    char buffer[4096];
    std::string result = "";
    
    // 调用外部程序并读取输出
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "AI 大脑连接失败...";
    
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    
    // 解析返回的 JSON 字符串，提取 "response" 字段的内容
    size_t pos = result.find("\"response\":\"");
    if (pos != std::string::npos) {
        size_t start = pos + 12;
        size_t end = result.find("\"", start);
        if (end != std::string::npos) {
            return result.substr(start, end - start);
        }
    }
    return "AI 解析失败，返回：" + result;
}
// ---------------------------------------------------------------------------
// 处理线程：批量取帧 → 锁外处理
//
// 与改造前对比：
//   旧：pop() 一次 1 帧、1 次加锁/解锁、空队列 sleep_for(10ms)
//   新：popBatch() 一次最多 32 帧、1 次加锁/解锁、空队列在条件变量上挂起
// ---------------------------------------------------------------------------
void processThread() {
    static constexpr std::size_t kBatchSize = 32;

    // 批缓冲放栈上：32 × 16 B = 512 B，常驻 L1，零分配
    can_frame batch[kBatchSize];

    std::uint64_t lastDropped = 0;
    auto lastReport = std::chrono::steady_clock::now();

    AlertLimiter alertBad;
    AlertLimiter alertBlacklist;
    AlertLimiter alertBruteforce;

    while (g_running.load(std::memory_order_relaxed)) {

        // ===================================================================
        // ① 唯一的临界区：一次抢锁，最多搬走 32 帧
        //    · 队列非空 → 立即返回，锁内只做 32 次 16 B 搬运 + 索引推进
        //    · 队列为空 → 在条件变量上挂起 ≤50 ms，线程进入睡眠态，
        //                 不消耗 CPU 时间片。这就是删掉 sleep_for(10ms) 的原因。
        // ===================================================================
        const std::size_t n = g_queue.popBatch(batch, kBatchSize);

        // 超时且无数据：回到循环顶部检查退出标志。
        // 这里不要再 sleep —— 挂起逻辑已经在 popBatch 内部完成了。
        if (n == 0) continue;

        // ===================================================================
        // ② 从这里往下全部在锁外：解析、检测、日志、I/O 都不再阻塞生产者。
        //    这一批处理得再慢，接收线程也能继续 push，两个线程彻底解耦。
        // ===================================================================
        for (std::size_t i = 0; i < n; ++i) {
            const can_frame& frame = batch[i];

            // 错误帧（总线错误/控制器状态变化）单独处理，不参与 ID 匹配
            if (frame.can_id & CAN_ERR_FLAG) continue;

            // 剥掉 EFF/RTR/ERR 标志位，拿到真正的 29 位仲裁 ID。
            // 不剥的话，一个 RTR 帧 0x3C0 的 can_id 是 0x400003C0，黑名单直接绕过。
            const std::uint32_t id = frame.can_id & CAN_EFF_MASK;

            // 经典 CAN 的 DLC 9~15 在物理上都表示 8 字节，显式钳位。
            // 绝不能把报文里的长度字段直接当 memcpy 长度用。
            const std::uint8_t dlc = frame.can_dlc > CAN_MAX_DLEN
                                       ? CAN_MAX_DLEN
                                       : frame.can_dlc;

            CanFrame myFrame(id, dlc, frame.data);

            if (!myFrame.isValid()) {
                g_bad.fetch_add(1, std::memory_order_relaxed);
                if (alertBad.allow())
                    std::cout << "[WARN] 捕获到非法畸形报文，dlc=" << int(dlc) << '\n';
            }
            else if (id == 0x3C0) {
                g_blacklisted.fetch_add(1, std::memory_order_relaxed);
                if (alertBlacklist.allow())
                    std::cout << "[ERROR] 发现黑名单报文 0x3C0，已触发安全拦截！\n";
            }
            else if (id == 0x7E0 && dlc >= 2 && frame.data[1] == 0x27) {
                g_bruteforce.fetch_add(1, std::memory_order_relaxed);

                if (alertBruteforce.allow()) {
                    std::string prompt = "你是傲娇的车载二次元助手,请用一句话警告主人:汽车正在遭到黑客的UDS安全爆破攻击。";
                    std::cout << "[AI思考中...]" << std::endl;
                    std::string ai_reply = ask_ai(prompt);
                    std::cout << "[AI警告]" << ai_reply << "\n";
                }
            }
            else {
                // 正常帧不逐条打印：一次终端 write 是 10~100 µs 的系统调用，
                // 逐条打印会把批量优化带来的全部收益吃掉。
                // 调试时临时打开下面这行：
                // std::cout << "[INFO] 0x" << std::hex << id << std::dec << '\n';
                g_normal.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // ===================================================================
        // ③ 每处理完一批检查一次（非热路径），最多 1 s 汇总一次
        // ===================================================================
        const auto now = std::chrono::steady_clock::now();
        if (now - lastReport >= std::chrono::seconds(1)) {
            lastReport = now;

            const std::uint64_t dropped = g_dropped.load(std::memory_order_relaxed);
            const std::uint64_t normal  = g_normal.exchange(0, std::memory_order_relaxed);

            if (dropped != lastDropped) {
                std::cout << "[WARN] 队列溢出，累计丢弃 " << dropped << " 帧\n";
                lastDropped = dropped;
            }

            std::cout << "[STAT] 正常帧 " << normal << " 帧/s"
                      << " | 畸形 "   << g_bad.exchange(0)
                      << " | 黑名单 " << g_blacklisted.exchange(0)
                      << " | 爆破 "   << g_bruteforce.exchange(0) << '\n';
        }
    }
}

int main() {
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);

    const int s = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { std::perror("socket"); return 1; }

    // 强烈建议：把内核接收缓冲调大，给用户态留出更多余量
    // int rcvbuf = 1 << 20;
    // ::setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, "vcan0", IFNAMSIZ - 1);
    if (::ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        std::perror("ioctl(SIOCGIFINDEX)");
        ::close(s);
        return 1;
    }

    sockaddr_can addr{};
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        ::close(s);
        return 1;
    }

    std::cout << "=== CanMonitor（批量 + 条件变量）已启动，Ctrl-C 退出 ===\n";

    std::thread t1(receiveThread, s);
    std::thread t2(processThread);

    t1.join();   // 收到信号后：接收线程 ≤100 ms 退出
    t2.join();   // 处理线程 ≤50 ms 退出（popBatch 的超时上限）

    ::close(s);
    std::cout << "累计丢弃帧: " << g_dropped.load() << '\n';
    return 0;
}