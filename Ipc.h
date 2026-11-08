#pragma once
// ============================================================================
// Ipc.h —— can-gateway 与 alert-agent 之间的私有协议（v2）
//
// v2 变更（与 v1 不兼容，两端必须同时重编）：
//   · AlertMsg 增加 count 字段：窗口内命中次数，agent 可直接念出来
//   · StatsMsg 增加 udsRequests / replay / unlock 三个计数器
//   · AlertKind 增加 Replay 与 UnauthorizedUnlock
//
// 设计原则不变：
//   1. 固定长度 POD 报文，没有 JSON、没有字符串、没有解析器；
//   2. SOCK_SEQPACKET 保留消息边界；
//   3. 发送端 MSG_DONTWAIT，agent 卡住时只丢消息，绝不阻塞检测线程；
//   4. 接收端 SO_PEERCRED 校验对端 UID。
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
inline constexpr std::uint32_t kVersion = 2;

enum class Type : std::uint32_t {
    Stats = 1,       // 每秒一次聚合统计
    Alert = 2,       // 检测到事件
};

enum class AlertKind : std::uint32_t {
    Blacklist          = 1,   // 命中黑名单 ID（策略性，单帧）
    Bruteforce         = 2,   // 窗口内 0x27 请求超限（可含 NRC 关联）
    Malformed          = 3,   // DLC / 结构非法
    Replay             = 4,   // 短窗口内完全相同的报文重复
    UnauthorizedUnlock = 5,   // 爆破后出现 0x67 0x27 正响应 —— 最高危
};

struct Header {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t payloadSize;
};

struct StatsMsg {
    std::uint64_t normal;
    std::uint64_t bad;
    std::uint64_t blacklisted;
    std::uint64_t bruteforce;    // 本区间内触发的爆破告警次数
    std::uint64_t dropped;       // 用户态队列丢弃（累计）
    std::uint64_t busError;
    std::uint64_t rxOverflow;    // 控制器 RX 溢出（累计）
    std::uint64_t udsRequests;   // 原始 0x27 请求帧数（本区间）
    std::uint64_t replay;        // 重放告警次数（本区间）
    std::uint64_t unlock;        // 解锁成功次数（本区间）
    std::uint64_t tsNs;
};

struct AlertMsg {
    std::uint32_t id;
    std::uint32_t kind;
    std::uint32_t count;         // 窗口内命中次数，0 表示不适用
    std::uint32_t reserved;
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
    WouldBlock,   // 对端来不及收（EAGAIN），本次丢弃即可
    Broken,       // 对端已关闭或协议错误，需要重连
};

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

inline int listenUnix(const std::string& path, mode_t mode = 0660) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) return -1;

    ::unlink(path.c_str());

    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }

    ::chmod(path.c_str(), mode);      // UMask 会让它变成 0600，必须显式放开组权限

    if (::listen(fd, 4) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

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

    if (n == static_cast<ssize_t>(total))                     return SendResult::Ok;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))   return SendResult::WouldBlock;
    return SendResult::Broken;
}

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

inline bool peerUid(int fd, uid_t& uid) {
    struct ucred cred{};
    socklen_t len = sizeof cred;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    uid = cred.uid;
    return true;
}

inline std::uint64_t nowNs() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace ipc
