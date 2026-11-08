// ============================================================================
// alert-agent.cpp —— P2：无特权执行者（AI + TTS + HTTP）
//
// 相对 P1 的变化：
//   · TTS 改为系统级安装路径 /opt/can-sentinel/venv/bin/edge-tts
//     该目录 root:can-gw 0755，ye 只能读和执行，无法篡改（V-06 收口）
//   · 文案按告警类型区分，并带上窗口内命中次数
//   · 保留 500 ms 全局兜底限流（网关侧已按类型限流，这里只防极端洪泛）
//
// 进程权限：User=ye，无 CAP_*，看不到 CAN。
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
    // 系统级安装路径：root:can-gw 0755，ye 不可写
    std::string ttsBin    = "/opt/can-sentinel/venv/bin/edge-tts";
    std::string ttsVoice  = "zh-CN-XiaoyiNeural";
    uid_t       allowUid  = 0;
};

Config& cfgMutable() {
    static Config c = [] () {
        Config v;
        const char* s = nullptr;
        if ((s = std::getenv("IPC_PATH"))   != nullptr) v.ipcPath   = s;
        if ((s = std::getenv("OLLAMA_URL")) != nullptr) v.ollamaUrl = s;
        if ((s = std::getenv("REPORT_URL")) != nullptr) v.reportUrl = s;
        if ((s = std::getenv("TTS_BIN"))    != nullptr) v.ttsBin    = s;
        if ((s = std::getenv("TTS_VOICE"))  != nullptr) v.ttsVoice  = s;

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
constexpr auto kBackstop      = std::chrono::milliseconds(500);
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
    const int fd = ::mkstemp(tmpl);
    if (fd < 0) return std::string();
    ::close(fd);
    return std::string(tmpl);
}

std::string desktopRuntimeDir() {
    const char* sudoUid = std::getenv("SUDO_UID");
    const std::string uid = (sudoUid != nullptr) ? sudoUid : std::to_string(::getuid());
    return "/run/user/" + uid;
}

const char* kindName(std::uint32_t kind) {
    switch (static_cast<ipc::AlertKind>(kind)) {
        case ipc::AlertKind::Blacklist:          return "Blacklist";
        case ipc::AlertKind::Bruteforce:         return "Bruteforce";
        case ipc::AlertKind::Malformed:          return "Malformed";
        case ipc::AlertKind::Replay:             return "Replay";
        case ipc::AlertKind::UnauthorizedUnlock: return "UnauthorizedUnlock";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// 文案属于表现层：网关只发 {id, kind, count}，怎么讲由这里决定
// ---------------------------------------------------------------------------
std::string promptFor(std::uint32_t kind, std::uint32_t count) {
    const std::string n = std::to_string(count);

    switch (static_cast<ipc::AlertKind>(kind)) {
        case ipc::AlertKind::Bruteforce:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "刚刚一秒内抓到 " + n + " 次 UDS 27 安全访问请求,"
                   "有人在暴力破解诊断权限!";
        case ipc::AlertKind::UnauthorizedUnlock:
            return "你是傲娇的车载二次元助手,请用一句话严肃警告主人:"
                   "安全访问已经被攻破,攻击者拿到了诊断权限,请立刻靠边停车!";
        case ipc::AlertKind::Replay:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "检测到报文重放,同一帧在瞬间重复了 " + n + " 次。";
        case ipc::AlertKind::Blacklist:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "检测到黑名单报文 0x3C0,已经拦截。";
        case ipc::AlertKind::Malformed:
            return "你是傲娇的车载二次元助手,请用一句话警告主人:"
                   "检测到非法畸形报文。";
    }
    return "你是傲娇的车载二次元助手,请用一句话警告主人:检测到未知异常。";
}

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
        ",\"dropped\":"     + std::to_string(s.dropped) +
        ",\"udsRequests\":" + std::to_string(s.udsRequests) +
        ",\"replay\":"      + std::to_string(s.replay) +
        ",\"unlock\":"      + std::to_string(s.unlock) + "}";

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
        std::fprintf(stderr, "[TTS] 合成失败 bin=%s timeout=%d exit=%d sig=%d\n",
                     cfg().ttsBin.c_str(), int(tts.timedOut), tts.exitCode, tts.termSig);
        ::unlink(path.c_str());
        return false;
    }

    // 🚨 直接调用 system，绕过 ProcessRunner 的环境丢失坑
    std::string play_cmd = "XDG_RUNTIME_DIR=/run/user/1000 PULSE_SERVER=unix:/run/user/1000/pulse/native /usr/bin/mpg123 -q " + path;
    int play_ret = system(play_cmd.c_str());
    
    // 播放完毕，立刻清理临时音频文件
    ::unlink(path.c_str());

    // system 返回 0 代表执行成功
    if (play_ret != 0) {
        std::fprintf(stderr, "[TTS 播放失败] system_ret=%d\n", play_ret);
        return false;
    }

    return true;
} // 这是 speak 函数的结束大括号

// ---------------------------------------------------------------------------
void workerThread() {
    ipc::AlertMsg a{};
    std::chrono::steady_clock::time_point last{};

    while (g_running.load(std::memory_order_acquire)) {
        if (g_alertQueue.popBatch(&a, 1) == 0) continue;

        const auto now = std::chrono::steady_clock::now();
        if (now - last < kBackstop) continue;      // 极端洪泛的兜底
        last = now;

        std::fprintf(stderr, "[ALERT] kind=%s id=0x%X count=%u\n",
                     kindName(a.kind), a.id, a.count);

        std::string reply;
        if (!askAi(promptFor(a.kind, a.count), reply)) continue;
        if (!g_running.load(std::memory_order_acquire)) break;

        std::fprintf(stderr, "[AI] %s\n", reply.c_str());

        postLog(reply);
        if (!g_running.load(std::memory_order_acquire)) break;
        speak(reply);
    }
}

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
void serveConnection(int c) {
    ipc::Packet pkt{};

    while (g_running.load(std::memory_order_acquire)) {
        ssize_t n = 0;
        if (!ipc::recvPacket(c, pkt, n)) {
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;
                break;
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
                g_alertQueue.push(a);
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

    // 启动自检：TTS 必须是系统级安装，且当前用户不能写它
    {
        struct stat st{};
        if (::stat(cfg().ttsBin.c_str(), &st) != 0) {
            std::fprintf(stderr, "[TTS] 找不到 %s，请先运行 deploy-tts.sh\n",
                         cfg().ttsBin.c_str());
        } else if ((st.st_mode & S_IWOTH) || (st.st_mode & S_IWGRP)) {
            std::fprintf(stderr,
                "[TTS] 警告：%s 对组或其他用户可写，存在被篡改风险\n",
                cfg().ttsBin.c_str());
        }
    }

    const int listenFd = ipc::listenUnix(cfg().ipcPath, 0660);
    if (listenFd < 0) {
        std::perror("listenUnix");
        std::fprintf(stderr,
            "提示：目录应存在且属于当前用户，例如\n"
            "  sudo install -d -o ye -g can-gw -m 0750 /run/can-sentinel\n");
        return 1;
    }

    std::fprintf(stderr,
        "=== alert-agent (P2) ===\n"
        "  socket  : %s\n"
        "  Ollama  : %s\n"
        "  上报    : %s\n"
        "  TTS     : %s\n"
        "  允许 UID: %u (以及 root)\n",
        cfg().ipcPath.c_str(), cfg().ollamaUrl.c_str(),
        cfg().reportUrl.c_str(), cfg().ttsBin.c_str(),
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
        if (peer != 0 && peer != cfg().allowUid) {
            std::fprintf(stderr, "[IPC] 拒绝 UID=%u 的连接\n",
                         static_cast<unsigned>(peer));
            ::close(c);
            continue;
        }

        std::fprintf(stderr, "[IPC] 已接受来自 UID=%u 的连接\n",
                     static_cast<unsigned>(peer));
        serveConnection(c);
        ::close(c);
        std::fprintf(stderr, "[IPC] 连接已断开\n");
    }

    ::close(listenFd);
    ::unlink(cfg().ipcPath.c_str());

    tWorker.join();
    tPost.join();

    std::fprintf(stderr, "=== alert-agent 退出 ===\n");
    return 0;
}
