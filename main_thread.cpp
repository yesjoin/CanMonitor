// ============================================================================
// main_thread.cpp —— CAN 安全网关（P0 版本）
//
// 线程模型（检测与响应彻底解耦）：
//
//   receiveThread   poll + read              → push 到 g_queue
//   processThread   popBatch(32) + 规则检测   → 命中只做 O(1) 入队 g_alertQueue
//   responderThread 取告警 → AI → 播报 → 日志  （可以慢、可以失败）
//   reportThread    每 1 s 聚合上报            （可观测性，与检测无关）
//
// 三条硬约束：
//   1. 检测线程里不允许出现任何阻塞调用：AI / TTS / HTTP / 终端输出全部外移；
//   2. 任何外部命令都走 ProcessRunner（argv 数组，永不经过 shell）；
//   3. 任何外部调用都有超时，超时整组 SIGKILL。
//
// 编译：
//   g++ -std=c++17 -O2 -pthread -Wall -Wextra main_thread.cpp -o can_gateway
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
#include <utility>

#include <linux/can.h>
#include <linux/can/error.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "CanFrame.h"
#include "ProcessRunner.h"
#include "RingBuffer.h"

namespace {

// ---------------------------------------------------------------------------
// 配置：全部可用环境变量覆盖，杜绝写死
// ---------------------------------------------------------------------------
struct Config {
    std::string iface     = "vcan0";
    std::string ollamaUrl = "http://127.0.0.1:11434/api/generate";
    std::string reportUrl = "http://127.0.0.1:5000/api/report";
    std::string ttsBin    = "/home/ye/.local/bin/edge-tts";
    std::string ttsVoice  = "zh-CN-XiaoyiNeural";
};

const Config& cfg() {
    static const Config c = [] () {
        Config v;
        const char* s = nullptr;
        if ((s = std::getenv("CAN_IFACE"))  != nullptr) v.iface     = s;
        if ((s = std::getenv("OLLAMA_URL")) != nullptr) v.ollamaUrl = s;
        if ((s = std::getenv("REPORT_URL")) != nullptr) v.reportUrl = s;
        if ((s = std::getenv("TTS_BIN"))    != nullptr) v.ttsBin    = s;
        if ((s = std::getenv("TTS_VOICE"))  != nullptr) v.ttsVoice  = s;
        return v;
    }();
    return c;
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------
constexpr std::size_t kQueueCapacity = 4096;   // 64 KB，10k fps 下约 400 ms
constexpr std::size_t kBatchSize     = 32;
constexpr std::size_t kAlertCapacity = 8;      // 告警合并：只保留最新几条

constexpr auto kAlertCooldown = std::chrono::seconds(5);    // 同一告警最短间隔
constexpr auto kAiTimeout     = std::chrono::seconds(65);   // curl --max-time 60 + 余量
constexpr auto kTtsTimeout    = std::chrono::seconds(30);
constexpr auto kHttpTimeout   = std::chrono::seconds(2);

const char* const kPromptBruteforce =
    "你是傲娇的车载二次元助手,请用一句话警告主人:"
    "汽车正在遭到黑客的UDS安全爆破攻击。";

// ---------------------------------------------------------------------------
// 全局共享状态
// ---------------------------------------------------------------------------
struct Alert {
    std::uint32_t id = 0;
    std::string   prompt;
};

RingBuffer<can_frame, kQueueCapacity> g_queue;
RingBuffer<Alert, kAlertCapacity>     g_alertQueue;

std::atomic<bool>          g_running{true};
std::atomic<std::uint64_t> g_dropped{0};       // 队列溢出丢弃（累计）
std::atomic<std::uint64_t> g_normal{0};
std::atomic<std::uint64_t> g_bad{0};
std::atomic<std::uint64_t> g_blacklisted{0};
std::atomic<std::uint64_t> g_bruteforce{0};
std::atomic<std::uint64_t> g_busError{0};      // CAN 错误帧
std::atomic<std::uint64_t> g_rxOverflow{0};    // 控制器 RX 溢出（累计）

void onSignal(int) { g_running.store(false, std::memory_order_release); }

// 同类告警限流：把"昂贵的动作"挡在最前面，队列就不会被洪泛灌满
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
    std::chrono::milliseconds          m_gap;
    std::chrono::steady_clock::time_point m_last{};
};

// ---------------------------------------------------------------------------
// 字符串工具
// ---------------------------------------------------------------------------
std::string jsonQuote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
    return out;
}

// 按字节截断，但不切断 UTF-8 多字节序列
std::string clipUtf8(const std::string& s, std::size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    std::size_t n = maxBytes;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    return s.substr(0, n);
}

// 独占创建临时文件：路径不可预测，且已存在时 mkstemp 会换一个名字，
// 从根上杜绝 /tmp 符号链接攻击
std::string makeTempFile() {
    char tmpl[] = "/tmp/can_alert_XXXXXX";
    const int fd = ::mkstemp(tmpl);
    if (fd < 0) return std::string();
    ::close(fd);
    return std::string(tmpl);
}

// sudo 下借用桌面用户的音频会话
std::string desktopRuntimeDir() {
    const char* sudoUid = std::getenv("SUDO_UID");
    const std::string uid = (sudoUid != nullptr) ? sudoUid : std::to_string(::getuid());
    return "/run/user/" + uid;
}

// ---------------------------------------------------------------------------
// 外部动作：全部走 ProcessRunner，全部有超时
// ---------------------------------------------------------------------------
bool askAi(const std::string& prompt, std::string& reply) {
    const std::string body =
        "{\"model\":\"qwen2:0.5b\",\"prompt\":" + jsonQuote(prompt) +
        ",\"stream\":false}";

    const ProcessRunner::Result r = ProcessRunner::run(
        {"curl", "-s", "--max-time", "60",
         cfg().ollamaUrl,
         "-d", body},
        kAiTimeout, 1u << 20);

    if (!r.ok()) {
        std::fprintf(stderr, "[AI] 调用失败 spawned=%d timeout=%d exit=%d sig=%d\n",
                     int(r.spawned), int(r.timedOut), r.exitCode, r.termSig);
        return false;
    }

    // Ollama 返回 {"response":"...","done":true}
    const std::string key = "\"response\":\"";
    const std::size_t pos = r.out.find(key);
    if (pos == std::string::npos) return false;

    std::string text;
    std::size_t i = pos + key.size();
    while (i < r.out.size() && r.out[i] != '"') {
        if (r.out[i] == '\\' && i + 1 < r.out.size()) {
            switch (r.out[i + 1]) {
                case 'n':  text += '\n'; break;
                case 't':  text += '\t'; break;
                case 'r':  text += '\r'; break;
                case '"':  text += '"';  break;
                case '\\': text += '\\'; break;
                case '/':  text += '/';  break;
                default:   text += r.out[i + 1]; break;
            }
            i += 2;
        } else {
            text += r.out[i++];
        }
    }
    if (text.empty()) return false;

    reply = std::move(text);
    return true;
}

bool speak(const std::string& text) {
    const std::string clipped = clipUtf8(text, 200);   // 别让 TTS 念一分钟
    if (clipped.empty()) return false;

    const std::string path = makeTempFile();
    if (path.empty()) return false;

    // 参数是独立的 argv 元素：文本里的引号、分号、$() 都只是普通字节
    const ProcessRunner::Result tts = ProcessRunner::run(
        {cfg().ttsBin, "--text", clipped,
         "--voice", cfg().ttsVoice,
         "--write-media", path},
        kTtsTimeout, 4096, false);

    if (!tts.ok()) {
        std::fprintf(stderr, "[TTS] 合成失败 timeout=%d exit=%d sig=%d\n",
                     int(tts.timedOut), tts.exitCode, tts.termSig);
        ::unlink(path.c_str());
        return false;
    }

    // 用 /usr/bin/env 注入 XDG_RUNTIME_DIR，而不是拼 shell 字符串
    const ProcessRunner::Result play = ProcessRunner::run(
        {"/usr/bin/env", "XDG_RUNTIME_DIR=" + desktopRuntimeDir(),
         "mpg123", "-q", path},
        kTtsTimeout, 4096, false);

    ::unlink(path.c_str());

    if (!play.ok()) {
        std::fprintf(stderr, "[TTS] 播放失败 timeout=%d exit=%d\n",
                     int(play.timedOut), play.exitCode);
        return false;
    }
    return true;
}

void postLog(const std::string& text) {
    const std::string body = "{\"log\":" + jsonQuote(clipUtf8(text, 500)) + "}";
    const ProcessRunner::Result r = ProcessRunner::run(
        {"curl", "-s", "--max-time", "2",
         "-H", "Content-Type: application/json",
         "-d", body,
         cfg().reportUrl},
        kHttpTimeout, 4096, false);

    if (!r.ok()) {
        std::fprintf(stderr, "[HTTP] 告警上报失败 exit=%d timeout=%d\n",
                     r.exitCode, int(r.timedOut));
    }
}

// ---------------------------------------------------------------------------
// 接收线程：唯一的职责是"尽快把帧搬进队列"
// ---------------------------------------------------------------------------
void receiveThread(int s) {
    can_frame frame{};

    pollfd pfd{};
    pfd.fd     = s;
    pfd.events = POLLIN;

    while (g_running.load(std::memory_order_acquire)) {
        const int rc = ::poll(&pfd, 1, 100);      // 100 ms 超时，保证能响应退出
        if (rc < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            g_running.store(false, std::memory_order_release);
            break;
        }
        if (rc == 0) continue;                    // 超时，无数据
        if ((pfd.revents & POLLIN) == 0) {        // POLLERR / POLLHUP：接口 down
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
        if (n != static_cast<ssize_t>(sizeof frame)) continue;   // 短读/尺寸异常

        if (!g_queue.push(frame)) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// 检测线程：只做 O(1) 的工作，绝不阻塞
// ---------------------------------------------------------------------------
void processThread() {
    can_frame batch[kBatchSize];
    AlertLimiter alertLimiter(kAlertCooldown);

    while (g_running.load(std::memory_order_acquire)) {
        const std::size_t n = g_queue.popBatch(batch, kBatchSize);
        if (n == 0) continue;

        for (std::size_t i = 0; i < n; ++i) {
            const can_frame& f = batch[i];

            // 错误帧：总线错误 / 控制器状态变化，单独统计
            if (f.can_id & CAN_ERR_FLAG) {
                g_busError.fetch_add(1, std::memory_order_relaxed);
                if ((f.can_id & CAN_ERR_CRTL) &&
                    (f.data[1] & CAN_ERR_CRTL_RX_OVERFLOW)) {
                    g_rxOverflow.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }

            // 剥掉 EFF/RTR/ERR 标志位，拿到真正的仲裁 ID
            const std::uint32_t id = f.can_id & CAN_EFF_MASK;

            // 经典 CAN 的 DLC 9~15 物理上都表示 8 字节，显式钳位
            const std::uint8_t dlc =
                (f.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : f.can_dlc;

            CanFrame myFrame(id, dlc, f.data);

            if (!myFrame.isValid()) {
                g_bad.fetch_add(1, std::memory_order_relaxed);
            } else if (id == 0x3C0) {
                g_blacklisted.fetch_add(1, std::memory_order_relaxed);
            } else if (id == 0x7E0 && dlc >= 2 && f.data[1] == 0x27) {
                g_bruteforce.fetch_add(1, std::memory_order_relaxed);

                // 只入队，不调用 AI、不写终端、不发 HTTP
                if (alertLimiter.allow()) {
                    Alert a;
                    a.id     = id;
                    a.prompt = kPromptBruteforce;
                    g_alertQueue.push(std::move(a));
                }
            } else {
                g_normal.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 响应线程：可以慢、可以失败，但永远拖不住检测线程
// ---------------------------------------------------------------------------
void responderThread() {
    Alert a;

    while (g_running.load(std::memory_order_acquire)) {
        if (g_alertQueue.popBatch(&a, 1) == 0) continue;   // 最多等 50 ms

        std::fprintf(stderr, "[ALERT] 命中 UDS 27 爆破, id=0x%X\n", a.id);

        std::string reply;
        if (!askAi(a.prompt, reply)) continue;

        // 关闭流程中不再做耗时的播报
        if (!g_running.load(std::memory_order_acquire)) break;

        std::fprintf(stderr, "[AI] %s\n", reply.c_str());

        postLog(reply);

        if (!g_running.load(std::memory_order_acquire)) break;
        speak(reply);
    }
}

// ---------------------------------------------------------------------------
// 上报线程：固定 1 s 节拍，与检测/告警完全解耦
// ---------------------------------------------------------------------------
void reportThread() {
    using clock = std::chrono::steady_clock;
    auto next = clock::now() + std::chrono::seconds(1);

    while (g_running.load(std::memory_order_acquire)) {
        std::this_thread::sleep_until(next);
        next += std::chrono::seconds(1);
        if (!g_running.load(std::memory_order_acquire)) break;

        const std::uint64_t normal      = g_normal.exchange(0, std::memory_order_relaxed);
        const std::uint64_t bad         = g_bad.exchange(0, std::memory_order_relaxed);
        const std::uint64_t blacklisted = g_blacklisted.exchange(0, std::memory_order_relaxed);
        const std::uint64_t bruteforce  = g_bruteforce.exchange(0, std::memory_order_relaxed);
        const std::uint64_t dropped     = g_dropped.load(std::memory_order_relaxed);
        const std::uint64_t busError    = g_busError.exchange(0, std::memory_order_relaxed);
        const std::uint64_t rxOverflow  = g_rxOverflow.load(std::memory_order_relaxed);

        const std::string body =
            "{\"normal\":"      + std::to_string(normal) +
            ",\"bad\":"         + std::to_string(bad) +
            ",\"blacklisted\":" + std::to_string(blacklisted) +
            ",\"bruteforce\":"  + std::to_string(bruteforce) +
            ",\"dropped\":"     + std::to_string(dropped) + "}";

        ProcessRunner::run(
            {"curl", "-s", "--max-time", "1",
             "-H", "Content-Type: application/json",
             "-d", body,
             cfg().reportUrl},
            kHttpTimeout, 4096, false);

        std::fprintf(stderr,
            "[STAT] normal=%llu bad=%llu black=%llu brute=%llu "
            "drop=%llu busErr=%llu rxOv=%llu\n",
            static_cast<unsigned long long>(normal),
            static_cast<unsigned long long>(bad),
            static_cast<unsigned long long>(blacklisted),
            static_cast<unsigned long long>(bruteforce),
            static_cast<unsigned long long>(dropped),
            static_cast<unsigned long long>(busError),
            static_cast<unsigned long long>(rxOverflow));
    }
}

}  // namespace

// ---------------------------------------------------------------------------
int main() {
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);      // 写已关闭的管道不要直接杀进程

    // SOCK_CLOEXEC：所有 curl / edge-tts / mpg123 子进程都不会继承这个 socket
    const int s = ::socket(PF_CAN, SOCK_RAW | SOCK_CLOEXEC, CAN_RAW);
    if (s < 0) { std::perror("socket"); return 1; }

    // 内核接收缓冲放大，给用户态留余量
    int rcvbuf = 1 << 20;
    if (::setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) != 0) {
        std::perror("setsockopt(SO_RCVBUF)");      // 非致命
    }

    // 订阅错误帧，才能看到控制器 RX 溢出（内核侧丢帧的唯一可见信号）
    const canid_t errMask = CAN_ERR_MASK;
    ::setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &errMask, sizeof errMask);

    ifreq ifr{};
    // 用 snprintf 而不是 strncpy：接口名长度可控，且保证以 '\0' 结尾
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
        "=== CAN 安全网关 (P0) 启动 ===\n"
        "  接口     : %s\n"
        "  Ollama   : %s\n"
        "  上报     : %s\n"
        "  TTS      : %s (%s)\n"
        "  队列容量 : %zu 帧\n",
        cfg().iface.c_str(), cfg().ollamaUrl.c_str(),
        cfg().reportUrl.c_str(), cfg().ttsBin.c_str(),
        cfg().ttsVoice.c_str(), kQueueCapacity);

    std::thread tRecv(receiveThread, s);
    std::thread tProc(processThread);
    std::thread tResp(responderThread);
    std::thread tReport(reportThread);

    tRecv.join();      // ≤100 ms
    tProc.join();      // ≤50 ms
    tResp.join();      // 可能正在 AI/TTS，最长 kAiTimeout + 2*kTtsTimeout
    tReport.join();    // ≤1 s

    ::close(s);

    std::fprintf(stderr, "=== 已退出，累计丢弃 %llu 帧 ===\n",
                 static_cast<unsigned long long>(g_dropped.load()));
    return 0;
}
