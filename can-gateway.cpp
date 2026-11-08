// ============================================================================
// can-gateway.cpp —— P1：只负责"收 + 判"，不做任何网络 I/O
//
// 进程权限：User=can-gw，CapabilityBoundingSet=CAP_NET_RAW，
//           RestrictAddressFamilies=AF_UNIX AF_CAN
//           —— 即使被完全攻陷，也开不出一个 AF_INET socket，无法外联。
//
// 线程模型：
//   receiveThread  poll + read              → push g_queue
//   processThread  popBatch(32) + 规则检测   → 命中 push g_alertQueue (O(1))
//   ipcThread      每 1 s 发统计，命中即发告警 → AF_UNIX SOCK_SEQPACKET
//
// 编译：
//   g++ -std=c++17 -O2 -pthread -Wall -Wextra can-gateway.cpp -o can-gateway
// ============================================================================

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <linux/can.h>
#include <linux/can/error.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "CanFrame.h"
#include "Ipc.h"
#include "RingBuffer.h"

namespace {

// ---------------------------------------------------------------------------
struct Config {
    std::string iface   = "vcan0";
    std::string ipcPath = "/run/can-sentinel/ipc.sock";
};

const Config& cfg() {
    static const Config c = [] () {
        Config v;
        const char* s = nullptr;
        if ((s = std::getenv("CAN_IFACE")) != nullptr) v.iface   = s;
        if ((s = std::getenv("IPC_PATH"))  != nullptr) v.ipcPath = s;
        return v;
    }();
    return c;
}

// ---------------------------------------------------------------------------
constexpr std::size_t kQueueCapacity = 4096;   // 64 KB，10k fps 下约 400 ms
constexpr std::size_t kBatchSize     = 32;
constexpr std::size_t kAlertCapacity = 8;

constexpr auto kAlertCooldown = std::chrono::seconds(5);
constexpr auto kStatsPeriod   = std::chrono::seconds(1);
constexpr auto kReconnectGap  = std::chrono::seconds(1);

// ---------------------------------------------------------------------------
RingBuffer<can_frame, kQueueCapacity>     g_queue;
RingBuffer<ipc::AlertMsg, kAlertCapacity> g_alertQueue;

std::atomic<bool>          g_running{true};
std::atomic<std::uint64_t> g_normal{0};
std::atomic<std::uint64_t> g_bad{0};
std::atomic<std::uint64_t> g_blacklisted{0};
std::atomic<std::uint64_t> g_bruteforce{0};
std::atomic<std::uint64_t> g_dropped{0};
std::atomic<std::uint64_t> g_busError{0};
std::atomic<std::uint64_t> g_rxOverflow{0};

void onSignal(int) { g_running.store(false, std::memory_order_release); }

class AlertLimiter {
public:
    explicit AlertLimiter(std::chrono::milliseconds gap) : m_gap(gap) {}
    bool allow() {
        const auto now = std::chrono::steady_clock::now();
        if (now - m_last < m_gap) return false;
        m_last = now;
        return true;
    }
private:
    std::chrono::milliseconds             m_gap;
    std::chrono::steady_clock::time_point m_last{};
};

// ---------------------------------------------------------------------------
// 接收线程
// ---------------------------------------------------------------------------
void receiveThread(int s) {
    can_frame frame{};

    pollfd pfd{};
    pfd.fd     = s;
    pfd.events = POLLIN;

    while (g_running.load(std::memory_order_acquire)) {
        const int rc = ::poll(&pfd, 1, 100);
        if (rc < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            g_running.store(false, std::memory_order_release);
            break;
        }
        if (rc == 0) continue;
        if ((pfd.revents & POLLIN) == 0) {
            std::fprintf(stderr, "[CAN] 接口异常 revents=0x%x\n",
                         static_cast<unsigned>(pfd.revents));
            g_running.store(false, std::memory_order_release);
            break;
        }

        const ssize_t n = ::read(s, &frame, sizeof frame);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            std::perror("read");
            g_running.store(false, std::memory_order_release);
            break;
        }
        if (n != static_cast<ssize_t>(sizeof frame)) continue;

        if (!g_queue.push(frame)) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// 检测线程：只读内存、只做判断，没有任何系统调用
// ---------------------------------------------------------------------------
void processThread() {
    can_frame batch[kBatchSize];
    AlertLimiter alertLimiter(kAlertCooldown);

    while (g_running.load(std::memory_order_acquire)) {
        const std::size_t n = g_queue.popBatch(batch, kBatchSize);
        if (n == 0) continue;

        for (std::size_t i = 0; i < n; ++i) {
            const can_frame& f = batch[i];

            if (f.can_id & CAN_ERR_FLAG) {
                g_busError.fetch_add(1, std::memory_order_relaxed);
                if ((f.can_id & CAN_ERR_CRTL) &&
                    (f.data[1] & CAN_ERR_CRTL_RX_OVERFLOW)) {
                    g_rxOverflow.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }

            const std::uint32_t id = f.can_id & CAN_EFF_MASK;
            const std::uint8_t  dlc =
                (f.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : f.can_dlc;

            CanFrame myFrame(id, dlc, f.data);

            if (!myFrame.isValid()) {
                g_bad.fetch_add(1, std::memory_order_relaxed);
            } else if (id == 0x3C0) {
                g_blacklisted.fetch_add(1, std::memory_order_relaxed);
            } else if (id == 0x7E0 && dlc >= 2 && f.data[1] == 0x27) {
                g_bruteforce.fetch_add(1, std::memory_order_relaxed);

                if (alertLimiter.allow()) {
                    ipc::AlertMsg a{};
                    a.id   = id;
                    a.kind = static_cast<std::uint32_t>(ipc::AlertKind::Bruteforce);
                    a.tsNs = ipc::nowNs();
                    g_alertQueue.push(a);          // POD 拷贝，纳秒级
                }
            } else {
                g_normal.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPC 线程：唯一的出口。agent 不在时只丢消息，绝不阻塞。
// ---------------------------------------------------------------------------
void ipcThread() {
    using clock = std::chrono::steady_clock;

    int  fd = -1;
    auto nextConnect = clock::now();
    auto nextStats   = clock::now() + kStatsPeriod;

    ipc::AlertMsg pending{};
    bool hasPending = false;
    bool warnedDown = false;

    while (g_running.load(std::memory_order_acquire)) {

        // ---- 连接维护：断开就每秒重试一次 --------------------------------
        if (fd < 0 && clock::now() >= nextConnect) {
            fd = ipc::connectUnix(cfg().ipcPath);
            nextConnect = clock::now() + kReconnectGap;

            if (fd >= 0 && warnedDown) {
                std::fprintf(stderr, "[IPC] 已连接 %s\n", cfg().ipcPath.c_str());
                warnedDown = false;
            } else if (fd < 0 && !warnedDown) {
                std::fprintf(stderr, "[IPC] 等待 alert-agent: %s\n",
                             cfg().ipcPath.c_str());
                warnedDown = true;
            }
        }

        // ---- 取告警：空队列时阻塞 ≤50 ms，避免忙等 ----------------------
        if (!hasPending) {
            hasPending = (g_alertQueue.popBatch(&pending, 1) != 0);
        } else if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // ---- 发送告警 ----------------------------------------------------
        if (hasPending && fd >= 0) {
            switch (ipc::sendPacket(fd, ipc::Type::Alert, pending)) {
                case ipc::SendResult::Ok:
                    hasPending = false;
                    break;
                case ipc::SendResult::WouldBlock:
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    break;
                case ipc::SendResult::Broken:
                    ::close(fd);
                    fd = -1;
                    nextConnect = clock::now() + kReconnectGap;
                    break;
            }
        }

        // ---- 每秒统计：无论有没有连上都消费计数器，避免重连后出现尖峰 ----
        if (clock::now() >= nextStats) {
            nextStats = clock::now() + kStatsPeriod;

            ipc::StatsMsg s{};
            s.normal      = g_normal.exchange(0, std::memory_order_relaxed);
            s.bad         = g_bad.exchange(0, std::memory_order_relaxed);
            s.blacklisted = g_blacklisted.exchange(0, std::memory_order_relaxed);
            s.bruteforce  = g_bruteforce.exchange(0, std::memory_order_relaxed);
            s.dropped     = g_dropped.load(std::memory_order_relaxed);
            s.busError    = g_busError.exchange(0, std::memory_order_relaxed);
            s.rxOverflow  = g_rxOverflow.load(std::memory_order_relaxed);
            s.tsNs        = ipc::nowNs();

            std::fprintf(stderr,
                "[STAT] normal=%llu bad=%llu black=%llu brute=%llu "
                "drop=%llu busErr=%llu rxOv=%llu\n",
                static_cast<unsigned long long>(s.normal),
                static_cast<unsigned long long>(s.bad),
                static_cast<unsigned long long>(s.blacklisted),
                static_cast<unsigned long long>(s.bruteforce),
                static_cast<unsigned long long>(s.dropped),
                static_cast<unsigned long long>(s.busError),
                static_cast<unsigned long long>(s.rxOverflow));

            if (fd >= 0 &&
                ipc::sendPacket(fd, ipc::Type::Stats, s) == ipc::SendResult::Broken) {
                ::close(fd);
                fd = -1;
                nextConnect = clock::now() + kReconnectGap;
            }
        }
    }

    if (fd >= 0) ::close(fd);
}

}  // namespace

// ---------------------------------------------------------------------------
int main() {
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    const int s = ::socket(PF_CAN, SOCK_RAW | SOCK_CLOEXEC, CAN_RAW);
    if (s < 0) { std::perror("socket(AF_CAN)"); return 1; }

    int rcvbuf = 1 << 20;
    if (::setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) != 0) {
        std::perror("setsockopt(SO_RCVBUF)");
    }

    const canid_t errMask = CAN_ERR_MASK;
    ::setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &errMask, sizeof errMask);

    ifreq ifr{};
    std::snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", cfg().iface.c_str());
    if (::ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        std::perror("ioctl(SIOCGIFINDEX)");
        ::close(s);
        return 1;
    }

    sockaddr_can addr{};
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind");
        ::close(s);
        return 1;
    }

    std::fprintf(stderr,
        "=== can-gateway 启动 ===\n"
        "  接口 : %s\n"
        "  IPC  : %s\n"
        "  队列 : %zu 帧\n",
        cfg().iface.c_str(), cfg().ipcPath.c_str(), kQueueCapacity);

    std::thread tRecv(receiveThread, s);
    std::thread tProc(processThread);
    std::thread tIpc(ipcThread);

    tRecv.join();
    tProc.join();
    tIpc.join();

    ::close(s);
    std::fprintf(stderr, "=== can-gateway 退出，累计丢弃 %llu 帧 ===\n",
                 static_cast<unsigned long long>(g_dropped.load()));
    return 0;
}
