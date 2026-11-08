// ============================================================================
// can-gateway.cpp —— P2：有状态检测
//
// 相对 P1 的变化：
//   · 引入 detection::StatefulDetector（滑动窗口 + NRC 关联 + 重放）
//   · 告警按类型分别限流，Unlock 类优先级最高（1 s），Replay 最低（30 s）
//   · 统计新增 udsRequests / replay / unlock 三个维度
//
// 进程权限不变：User=can-gw，CAP_NET_RAW，AF_UNIX + AF_CAN，无网络。
//
// 编译：
//   g++ -std=c++17 -O2 -pthread -Wall -Wextra can-gateway.cpp -o can-gateway
// ============================================================================

#include <algorithm>
#include <array>
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
#include "Detection.h"
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

std::uint64_t envU64(const char* name, std::uint64_t def) {
    const char* s = std::getenv(name);
    if (s == nullptr || *s == '\0') return def;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 10);
    if (end == s || (end != nullptr && *end != '\0')) return def;
    return static_cast<std::uint64_t>(v);
}

bool envBool(const char* name, bool def) {
    const char* s = std::getenv(name);
    if (s == nullptr || *s == '\0') return def;
    return !(std::strcmp(s, "0") == 0 ||
             std::strcmp(s, "false") == 0 ||
             std::strcmp(s, "no") == 0);
}

detection::Config loadDetectionConfig() {
    detection::Config c;
    c.windowNs        = envU64("UDS_WINDOW_MS", 1000) * 1000000ull;
    c.reqThreshold    = static_cast<std::size_t>(
                            std::max<std::uint64_t>(1, envU64("UDS_REQ_THRESHOLD", 5)));
    c.nrcThreshold    = static_cast<std::size_t>(
                            std::max<std::uint64_t>(1, envU64("UDS_NRC_THRESHOLD", 3)));
    c.requireNrc      = envBool("UDS_REQUIRE_NRC", true);
    c.replayWindowNs  = envU64("REPLAY_WINDOW_MS", 200) * 1000000ull;
    c.replayThreshold = static_cast<std::size_t>(
                            std::max<std::uint64_t>(1, envU64("REPLAY_THRESHOLD", 8)));
    return c;
}

// ---------------------------------------------------------------------------
constexpr std::size_t kQueueCapacity = 4096;
constexpr std::size_t kBatchSize     = 32;
constexpr std::size_t kAlertCapacity = 8;

constexpr auto kStatsPeriod  = std::chrono::seconds(1);
constexpr auto kReconnectGap = std::chrono::seconds(1);

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
std::atomic<std::uint64_t> g_udsRequests{0};
std::atomic<std::uint64_t> g_replay{0};
std::atomic<std::uint64_t> g_unlock{0};

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

// 按告警类型分别限流：Unlock 最紧急（1 s 一次），Replay 最吵（30 s 一次）
bool allowAlert(ipc::AlertKind kind) {
    static std::array<AlertLimiter, 6> limiters = {{
        AlertLimiter(std::chrono::hours(1)),      // 0：占位
        AlertLimiter(std::chrono::seconds(5)),    // 1 Blacklist
        AlertLimiter(std::chrono::seconds(5)),    // 2 Bruteforce
        AlertLimiter(std::chrono::seconds(5)),    // 3 Malformed
        AlertLimiter(std::chrono::seconds(30)),   // 4 Replay
        AlertLimiter(std::chrono::seconds(1)),    // 5 UnauthorizedUnlock
    }};
    const std::size_t i = static_cast<std::size_t>(kind);
    return i < limiters.size() && limiters[i].allow();
}

void pushAlert(std::uint32_t id, ipc::AlertKind kind,
               std::uint32_t count, std::uint64_t nowNs) {
    ipc::AlertMsg a{};
    a.id    = id;
    a.kind  = static_cast<std::uint32_t>(kind);
    a.count = count;
    a.tsNs  = nowNs;
    g_alertQueue.push(a);
}

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
// 检测线程：滑动窗口 + 状态机，全程只读内存
// ---------------------------------------------------------------------------
void processThread() {
    can_frame batch[kBatchSize];
    detection::StatefulDetector detector{loadDetectionConfig()};

    while (g_running.load(std::memory_order_acquire)) {
        const std::size_t n = g_queue.popBatch(batch, kBatchSize);
        if (n == 0) continue;

        for (std::size_t i = 0; i < n; ++i) {
            const can_frame& f = batch[i];
            const std::uint64_t now = ipc::nowNs();

            if (f.can_id & CAN_ERR_FLAG) {
                g_busError.fetch_add(1, std::memory_order_relaxed);
                if ((f.can_id & CAN_ERR_CRTL) &&
                    (f.data[1] & CAN_ERR_CRTL_RX_OVERFLOW)) {
                    g_rxOverflow.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }

            const std::uint32_t id  = f.can_id & CAN_EFF_MASK;
            const std::uint8_t  dlc =
                (f.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : f.can_dlc;

            CanFrame myFrame(id, dlc, f.data);

            if (!myFrame.isValid()) {
                g_bad.fetch_add(1, std::memory_order_relaxed);
                if (allowAlert(ipc::AlertKind::Malformed))
                    pushAlert(id, ipc::AlertKind::Malformed, 0, now);
                continue;
            }

            // 策略性黑名单：单帧即可判定，不需要窗口
            if (id == 0x3C0) {
                g_blacklisted.fetch_add(1, std::memory_order_relaxed);
                if (allowAlert(ipc::AlertKind::Blacklist))
                    pushAlert(id, ipc::AlertKind::Blacklist, 0, now);
                continue;
            }

            // 行为检测：必须让每一帧都进入状态机，包括 ECU 的响应帧
            const detection::Verdict v = detector.feed(f, now);
            if (v.udsRequest) g_udsRequests.fetch_add(1, std::memory_order_relaxed);

            if (v.alert) {
                switch (v.event.kind) {
                    case ipc::AlertKind::Bruteforce:
                        g_bruteforce.fetch_add(1, std::memory_order_relaxed);
                        break;
                    case ipc::AlertKind::UnauthorizedUnlock:
                        g_unlock.fetch_add(1, std::memory_order_relaxed);
                        break;
                    case ipc::AlertKind::Replay:
                        g_replay.fetch_add(1, std::memory_order_relaxed);
                        break;
                    default:
                        break;
                }
                if (allowAlert(v.event.kind)) {
                    pushAlert(v.event.id, v.event.kind, v.event.count, now);
                }
            }

            g_normal.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

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

        if (!hasPending) {
            hasPending = (g_alertQueue.popBatch(&pending, 1) != 0);
        } else if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

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
            s.udsRequests = g_udsRequests.exchange(0, std::memory_order_relaxed);
            s.replay      = g_replay.exchange(0, std::memory_order_relaxed);
            s.unlock      = g_unlock.exchange(0, std::memory_order_relaxed);
            s.tsNs        = ipc::nowNs();

            std::fprintf(stderr,
                "[STAT] normal=%llu bad=%llu black=%llu brute=%llu "
                "uds=%llu replay=%llu unlock=%llu drop=%llu busErr=%llu rxOv=%llu\n",
                static_cast<unsigned long long>(s.normal),
                static_cast<unsigned long long>(s.bad),
                static_cast<unsigned long long>(s.blacklisted),
                static_cast<unsigned long long>(s.bruteforce),
                static_cast<unsigned long long>(s.udsRequests),
                static_cast<unsigned long long>(s.replay),
                static_cast<unsigned long long>(s.unlock),
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

    const detection::Config dc = loadDetectionConfig();
    std::fprintf(stderr,
        "=== can-gateway (P2 stateful) ===\n"
        "  接口     : %s\n"
        "  IPC      : %s\n"
        "  UDS 窗口 : %llu ms, 阈值 %zu 次, NRC 阈值 %zu\n"
        "  NRC 门控 : %s\n"
        "  重放窗口 : %llu ms, 阈值 %zu 次\n",
        cfg().iface.c_str(), cfg().ipcPath.c_str(),
        static_cast<unsigned long long>(dc.windowNs / 1000000ull),
        dc.reqThreshold, dc.nrcThreshold,
        dc.requireNrc ? "开" : "关",
        static_cast<unsigned long long>(dc.replayWindowNs / 1000000ull),
        dc.replayThreshold);

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
