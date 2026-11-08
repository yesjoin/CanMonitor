#pragma once
// ============================================================================
// Ipc.h —— can-gateway 与 alert-agent 之间的私有协议
//
// 设计原则：
//   1. 固定长度 POD 报文，没有 JSON、没有字符串、没有解析器。
//      网关只能发送"数字"，因此不存在任何注入面（路径、命令、HTML 都不例外）。
//   2. SOCK_SEQPACKET：保留消息边界，一次 send 对应一次 recv，
//      不需要自己做粘包/拆包。
//   3. 发送端 MSG_DONTWAIT：agent 卡住时网关只丢消息，绝不阻塞检测线程。
//   4. 接收端用 SO_PEERCRED 校验对端 UID，只有网关能连进来。
//
// 兼容性约束：两端必须用同一份 Ipc.h 编译，报文中带 version 校验。
// ============================================================================

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace ipc {

inline constexpr std::uint32_t kMagic   = 0x43414E47u;   // "CANG"
inline constexpr std::uint32_t kVersion = 1;

enum class Type : std::uint32_t {
    Stats = 1,       // 每秒一次聚合统计
    Alert = 2,       // 检测到攻击
};

enum class AlertKind : std::uint32_t {
    Blacklist  = 1,
    Bruteforce = 2,
    Malformed  = 3,
};

struct Header {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t payloadSize;
};

// 统计：全部是网关侧计数器的快照
struct StatsMsg {
    std::uint64_t normal;
    std::uint64_t bad;
    std::uint64_t blacklisted;
    std::uint64_t bruteforce;
    std::uint64_t dropped;       // 用户态队列丢弃（累计）
    std::uint64_t busError;      // CAN 错误帧
    std::uint64_t rxOverflow;    // 控制器 RX 溢出（累计）
    std::uint64_t tsNs;          // 发送时刻（steady_clock，同机可比）
};

// 告警：只有 ID / 类型 / 时间，没有文本。
// "说什么"是表现层的事，归 agent；"发生了什么"是检测层的事，归网关。
struct AlertMsg {
    std::uint32_t id;
    std::uint32_t kind;
    std::uint64_t tsNs;
};

inline constexpr std::size_t kMaxPayload =
    (sizeof(StatsMsg) > sizeof(AlertMsg)) ? sizeof(StatsMsg) : sizeof(AlertMsg);

struct Packet {
    Header        header;
    std::uint8_t  payload[kMaxPayload];
};

static_assert(sizeof(Header) == 16, "Header 必须是 16 字节");
static_assert(kMaxPayload <= 128, "报文过大，检查结构体定义");

enum class SendResult {
    Ok,           // 已完整写入 socket 缓冲区
    WouldBlock,   // 对端来不及收，本次丢弃即可（EAGAIN）
    Broken,       // 对端已关闭或协议错误，需要重连
};

// ---------------------------------------------------------------------------
// 连接（客户端：网关）
// ---------------------------------------------------------------------------
inline int connectUnix(const std::string& path) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) return -1;

    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// ---------------------------------------------------------------------------
// 监听（服务端：agent）
//   mode 默认 0660：owner 是 agent，group 是 can-gw。
//   目录本身由 systemd 的 RuntimeDirectory 创建（0750，owner ye:can-gw）。
// ---------------------------------------------------------------------------
inline int listenUnix(const std::string& path, mode_t mode = 0660) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) return -1;

    ::unlink(path.c_str());          // 清理上次崩溃留下的陈旧 socket

    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }

    // 必须显式 chmod：systemd 的 UMask 会让 socket 默认是 0600，
    // 那样网关（另一个 UID，仅靠同组）连不进来。
    ::chmod(path.c_str(), mode);

    if (::listen(fd, 4) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// ---------------------------------------------------------------------------
// 发送
// ---------------------------------------------------------------------------
template <typename T>
inline SendResult sendPacket(int fd, Type type, const T& body) {
    static_assert(sizeof(T) <= kMaxPayload, "payload 超出 kMaxPayload");

    Packet p{};
    p.header.magic       = kMagic;
    p.header.version     = kVersion;
    p.header.type        = static_cast<std::uint32_t>(type);
    p.header.payloadSize = static_cast<std::uint32_t>(sizeof(T));
    std::memcpy(p.payload, &body, sizeof(T));

    const std::size_t total = sizeof(Header) + sizeof(T);
    const ssize_t n = ::send(fd, &p, total, MSG_NOSIGNAL | MSG_DONTWAIT);

    if (n == static_cast<ssize_t>(total))            return SendResult::Ok;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SendResult::WouldBlock;
    return SendResult::Broken;
}

// ---------------------------------------------------------------------------
// 接收（带校验）
//   received：底层 recv 的返回值，用于区分"超时"与"协议错误"
// ---------------------------------------------------------------------------
inline bool recvPacket(int fd, Packet& out, ssize_t& received) {
    received = ::recv(fd, &out, sizeof out, 0);

    if (received < static_cast<ssize_t>(sizeof(Header))) return false;
    if (out.header.magic   != kMagic)                    return false;
    if (out.header.version != kVersion)                  return false;
    if (out.header.payloadSize > kMaxPayload)            return false;
    if (received != static_cast<ssize_t>(sizeof(Header) + out.header.payloadSize))
        return false;

    return true;
}

// ---------------------------------------------------------------------------
// 对端身份：Linux 的 SO_PEERCRED
// ---------------------------------------------------------------------------
inline bool peerUid(int fd, uid_t& uid) {
    struct ucred cred{};
    socklen_t len = sizeof cred;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    uid = cred.uid;
    return true;
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------
inline std::uint64_t nowNs() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace ipc
