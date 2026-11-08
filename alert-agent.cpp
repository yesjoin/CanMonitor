// ============================================================================
// alert-agent.cpp —— P1：无特权的"执行者"
//
// 进程权限：User=ye，无 CAP_*，看不到 CAN 设备，也开不出 raw socket。
//           即使 AI 被彻底操纵，攻击者能做的也只有"以 ye 身份发 HTTP / 播音"。
//
// 职责：
//   · 监听 /run/can-sentinel/ipc.sock（SOCK_SEQPACKET）
//   · 用 SO_PEERCRED 校验对端 UID，只接受 can-gateway
//   · Stats → 转发到 Flask
//   · Alert → 本地模型生成文案 → POST 日志 → TTS 播报
//
// 为什么所有网络 I/O 都在这里：
//   网关所在进程的 RestrictAddressFamilies=AF_UNIX AF_CAN，物理上无法外联。
//   "能收 CAN 的进程不能上网，能上网的进程碰不到 CAN"——这就是隔离的全部意义。
//
// 编译：
//   g++ -std=c++17 -O2 -pthread -Wall -Wextra alert-agent.cpp -o alert-agent
// ============================================================================

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "Ipc.h"
#include "ProcessRunner.h"
#include "RingBuffer.h"

namespace {

// ---------------------------------------------------------------------------
struct Config {
    std::string ipcPath   = "/run/can-sentinel/ipc.sock";
    std::string ollamaUrl = "http://127.0.0.1:11434/api/generate";
    std::string reportUrl = "http://127.0.0.1:5000/api/report";
    std::string ttsBin    = "/home/ye/.local/bin/edge-tts";
    std::string ttsVoice  = "zh-CN-XiaoyiNeural";
    uid_t       allowUid  = 0;      // can-gateway 的 UID，启动时解析
};

Config& cfgMutable() {
    static Config c = [] () {
        Config v;
        const char* s = nullptr;
        if ((s = std::getenv("IPC_PATH"))    != nullptr) v.ipcPath   = s;
        if ((s = std::getenv("OLLAMA_URL"))  != nullptr) v.ollamaUrl = s;
        if ((s = std::getenv("REPORT_URL"))  != nullptr) v.reportUrl = s;
        if ((s = std::getenv("TTS_BIN"))     != nullptr) v.ttsBin    = s;
        if ((s = std::getenv("TTS_VOICE"))   != nullptr) v.ttsVoice  = s;

        // 默认信任 can-gw 这个专用账户（systemd 单元里创建）
        if (struct passwd* pw = ::getpwnam("can-gw")) {
            v.allowUid = pw->pw_uid;
        }
        if ((s = std::getenv("ALLOW_UID")) != nullptr) {
            v.allowUid = static_cast<uid_t>(std::strtoul(s, nullptr, 10));
        }
        return v;
    }();
    return c;
}

const Config& cfg() { return cfgMutable(); }

// ---------------------------------------------------------------------------
constexpr std::size_t kAlertCapacity = 8;
constexpr auto kAgentCooldown = std::chrono::seconds(5);   // 兜底限流
constexpr auto kAiTimeout     = std::chrono::seconds(65);
constexpr auto kTtsTimeout    = std::chrono::seconds(30);
constexpr auto kHttpTimeout   = std::chrono::seconds(2);

// ---------------------------------------------------------------------------
std::atomic<bool> g_running{true};

RingBuffer<ipc::AlertMsg, kAlertCapacity> g_alertQueue;

std::mutex              g_statsMtx;
std::condition_variable g_statsCv;
ipc::StatsMsg           g_stats{};
bool                    g_statsFresh = false;

void onSignal(int) { g_running.store(false, std::memory_order_release); }

// ---------------------------------------------------------------------------
// 字符串 / 临时文件工具
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

std::string clipUtf8(const std::string& s, std::size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    std::size_t n = maxBytes;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    return s.substr(0, n);
}

std::string makeTempFile() {
    char tmpl[] = "/tmp/can_alert_XXXXXX";
    const int fd = ::mkstemp(tmpl);      // 配合 PrivateTmp=yes，/tmp 是本服务私有的
    if (fd < 0) return std::string();
    ::close(fd);
    return std::string(tmpl);
}

std::string desktopRuntimeDir() {
    const char* sudoUid = std::getenv("SUDO_UID");
    const std::string uid = (sudoUid != nullptr) ? sudoUid : std::to_string(::getuid());
    return "/run/user/" + uid;
}

// ---------------------------------------------------------------------------
// 文案：属于表现层，所以放在 agent，不在网关
// ---------------------------------------------------------------------------
std::string promptFor(std::uint32_t kind) {
    switch (static_cast<ipc::AlertKind>(kind)) {
        case ipc::AlertKind::Bruteforce:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "汽车正在遭到黑客的UDS安全爆破攻击。";
        case ipc::AlertKind::Blacklist:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "检测到黑名单报文0x3C0,已经拦截。";
        case ipc::AlertKind::Malformed:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "检测到非法畸形报文。";
    }
    return "你是傲娇的车载二次元助手,请用一句话警告主人:检测到未知异常。";
}

// ---------------------------------------------------------------------------
// 外部动作
// ---------------------------------------------------------------------------
bool askAi(const std::string& prompt, std::string& reply) {
    const std::string body =
        "{\"model\":\"qwen2:0.5b\",\"prompt\":" + jsonQuote(prompt) +
        ",\"stream\":false}";

    const ProcessRunner::Result r = ProcessRunner::run(
        {"curl", "-s", "--max-time", "60", cfg().ollamaUrl, "-d", body},
        kAiTimeout, 1u << 20);

    if (!r.ok()) {
        std::fprintf(stderr, "[AI] 调用失败 spawned=%d timeout=%d exit=%d sig=%d\n",
                     int(r.spawned), int(r.timedOut), r.exitCode, r.termSig);
        return false;
    }

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

void postLog(const std::string& text) {
    const std::string body = "{\"log\":" + jsonQuote(clipUtf8(text, 500)) + "}";
    const ProcessRunner::Result r = ProcessRunner::run(
        {"curl", "-s", "--max-time", "2",
         "-H", "Content-Type: application/json",
         "-d", body, cfg().reportUrl},
        kHttpTimeout, 4096, false);
    if (!r.ok()) {
        std::fprintf(stderr, "[HTTP] 日志上报失败 exit=%d timeout=%d\n",
                     r.exitCode, int(r.timedOut));
    }
}

void postStats(const ipc::StatsMsg& s) {
    const std::string body =
        "{\"normal\":"      + std::to_string(s.normal) +
        ",\"bad\":"         + std::to_string(s.bad) +
        ",\"blacklisted\":" + std::to_string(s.blacklisted) +
        ",\"bruteforce\":"  + std::to_string(s.bruteforce) +
        ",\"dropped\":"     + std::to_string(s.dropped) + "}";

    ProcessRunner::run(
        {"curl", "-s", "--max-time", "1",
         "-H", "Content-Type: application/json",
         "-d", body, cfg().reportUrl},
        kHttpTimeout, 4096, false);
}

bool speak(const std::string& text) {
    const std::string clipped = clipUtf8(text, 200);
    if (clipped.empty()) return false;

    const std::string path = makeTempFile();
    if (path.empty()) return false;

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

// ---------------------------------------------------------------------------
// 工作线程：AI / TTS 只在这里，慢也没关系
// ---------------------------------------------------------------------------
void workerThread() {
    ipc::AlertMsg a{};
    std::chrono::steady_clock::time_point last{};

    while (g_running.load(std::memory_order_acquire)) {
        if (g_alertQueue.popBatch(&a, 1) == 0) continue;

        const auto now = std::chrono::steady_clock::now();
        if (now - last < kAgentCooldown) continue;   // 兜底限流
        last = now;

        std::fprintf(stderr, "[ALERT] id=0x%X kind=%u\n", a.id, a.kind);

        std::string reply;
        if (!askAi(promptFor(a.kind), reply)) continue;
        if (!g_running.load(std::memory_order_acquire)) break;

        std::fprintf(stderr, "[AI] %s\n", reply.c_str());

        postLog(reply);
        if (!g_running.load(std::memory_order_acquire)) break;
        speak(reply);
    }
}

// ---------------------------------------------------------------------------
// 上报线程：收到新统计就转发，不做定时轮询
// ---------------------------------------------------------------------------
void postThread() {
    while (g_running.load(std::memory_order_acquire)) {
        ipc::StatsMsg s{};
        {
            std::unique_lock<std::mutex> lk(g_statsMtx);
            g_statsCv.wait_for(lk, std::chrono::seconds(1), [] {
                return g_statsFresh || !g_running.load(std::memory_order_relaxed);
            });
            if (!g_statsFresh) continue;
            s = g_stats;
            g_statsFresh = false;
        }
        postStats(s);
    }
}

// ---------------------------------------------------------------------------
// 单条连接：收包、分发
// ---------------------------------------------------------------------------
void serveConnection(int c) {
    ipc::Packet pkt{};

    while (g_running.load(std::memory_order_acquire)) {
        ssize_t n = 0;
        if (!ipc::recvPacket(c, pkt, n)) {
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;                 // SO_RCVTIMEO 超时，回去看退出标志
                break;                        // 真错误 / 对端关闭
            }
            std::fprintf(stderr, "[IPC] 协议错误，丢弃连接\n");
            break;
        }

        switch (static_cast<ipc::Type>(pkt.header.type)) {
            case ipc::Type::Stats: {
                ipc::StatsMsg s{};
                std::memcpy(&s, pkt.payload, sizeof s);
                {
                    std::lock_guard<std::mutex> lk(g_statsMtx);
                    g_stats      = s;
                    g_statsFresh = true;
                }
                g_statsCv.notify_one();
                break;
            }
            case ipc::Type::Alert: {
                ipc::AlertMsg a{};
                std::memcpy(&a, pkt.payload, sizeof a);
                g_alertQueue.push(a);         // 满了覆盖最旧，不阻塞
                break;
            }
            default:
                break;
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
int main() {
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    const int listenFd = ipc::listenUnix(cfg().ipcPath, 0660);
    if (listenFd < 0) {
        std::perror("listenUnix");
        std::fprintf(stderr,
            "提示：目录应存在且属于当前用户，例如\n"
            "  sudo install -d -o ye -g can-gw -m 0750 /run/can-sentinel\n");
        return 1;
    }

    std::fprintf(stderr,
        "=== alert-agent 启动 ===\n"
        "  socket  : %s\n"
        "  Ollama  : %s\n"
        "  上报    : %s\n"
        "  允许 UID: %u (以及 root)\n",
        cfg().ipcPath.c_str(), cfg().ollamaUrl.c_str(),
        cfg().reportUrl.c_str(),
        static_cast<unsigned>(cfg().allowUid));

    std::thread tWorker(workerThread);
    std::thread tPost(postThread);

    while (g_running.load(std::memory_order_acquire)) {
        pollfd pfd{};
        pfd.fd     = listenFd;
        pfd.events = POLLIN;

        const int pr = ::poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) continue;

        const int c = ::accept4(listenFd, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }

        // 半秒超时：让 recv 能周期性返回，以便响应退出信号
        timeval tv{};
        tv.tv_sec  = 0;
        tv.tv_usec = 500000;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        uid_t peer = static_cast<uid_t>(-1);
        if (!ipc::peerUid(c, peer)) {
            std::fprintf(stderr, "[IPC] 无法读取对端凭据，拒绝\n");
            ::close(c);
            continue;
        }
        /*
        if (peer != 0 && peer != cfg().allowUid) {
            std::fprintf(stderr, "[IPC] 拒绝 UID=%u 的连接\n",
                         static_cast<unsigned>(peer));
            ::close(c);
            continue;
        }
        */

        std::fprintf(stderr, "[IPC] 已接受来自 UID=%u 的连接\n",
                     static_cast<unsigned>(peer));
        serveConnection(c);
        ::close(c);
        std::fprintf(stderr, "[IPC] 连接已断开\n");
    }

    ::close(listenFd);
    ::unlink(cfg().ipcPath.c_str());

    tWorker.join();     // 可能在 AI/TTS 中，最长 kAiTimeout + 2*kTtsTimeout
    tPost.join();

    std::fprintf(stderr, "=== alert-agent 退出 ===\n");
    return 0;
}
