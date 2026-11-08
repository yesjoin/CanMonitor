#pragma once
// ============================================================================
// Detection.h —— 有状态检测引擎（单线程使用，无需加锁）
//
// 三条检测线，各自解决一类"单帧看不出来"的攻击：
//
//   1. UDS 27 爆破：滑动窗口统计 0x7E0 上的 0x27 请求频率，
//      并关联 0x7E8 上的负响应 NRC 0x35（密钥无效）/ 0x36（尝试次数超限）。
//      —— 单独一帧 0x27 是正常诊断；一秒内 5 次并伴随 NRC 才是爆破。
//
//   2. 未授权解锁：爆破窗口内出现 0x67 0x27 正响应。
//      这是"已经攻破"的信号，优先级最高。
//
//   3. 重放：同一 ID 上完全相同的报文在短窗口内高频重复。
//      —— 必须做周期性豁免，否则每一个 10 ms 周期帧都会误报。
//
// 设计约束：
//   · 全部 O(1) 摊还，10k fps 下每帧开销约几十纳秒；
//   · 所有容器有硬上限，内存不随攻击流量增长；
//   · ISO-TP 只处理单帧（SF），多帧需要重组，不在本层范围内。
// ============================================================================

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <deque>

#include <linux/can.h>

#include "Ipc.h"

namespace detection {

// ---------------------------------------------------------------------------
struct Config {
    // UDS 27 爆破窗口
    std::uint64_t windowNs     = 1000000000ull;   // 1 s
    std::size_t   reqThreshold = 5;               // 窗口内请求次数阈值
    std::size_t   nrcThreshold = 3;               // 窗口内 NRC 0x35 次数阈值
    bool          requireNrc   = true;            // 是否要求出现 NRC 才判定

    // 重放窗口
    std::uint64_t replayWindowNs  = 200000000ull; // 200 ms
    std::size_t   replayThreshold = 8;            // 窗口内相同报文次数

    // 诊断寻址（11 位 ID 方案；29 位方案需另行配置）
    std::uint32_t udsReqBase  = 0x7E0;            // 0x7E0 .. 0x7E7
    std::uint32_t udsRespBase = 0x7E8;            // 0x7E8 .. 0x7EF

    // 重放表容量（必须是 2 的幂，便于取模）
    std::size_t replaySlots = 64;
};

struct Event {
    ipc::AlertKind kind = ipc::AlertKind::Malformed;
    std::uint32_t  id    = 0;
    std::uint32_t  count = 0;     // 窗口内命中次数
};

struct Verdict {
    bool  udsRequest = false;     // 本帧是 0x27 请求（供统计）
    bool  alert      = false;
    Event event;
};

// ---------------------------------------------------------------------------
// 固定跨度的时间窗口：只保留 span 内的样本，容量有硬上限。
// 用 deque 而不是 vector，是为了 front 端 O(1) 弹出。
// ---------------------------------------------------------------------------
class TimeWindow {
public:
    explicit TimeWindow(std::uint64_t spanNs) : m_span(spanNs) {}

    void push(std::uint64_t now) {
        evict(now);
        m_stamps.push_back(now);
        // 攻击者可以打到 100k 帧/秒；封顶保证内存有界，计数饱和即可
        if (m_stamps.size() > kMaxSamples) m_stamps.pop_front();
    }

    std::size_t size(std::uint64_t now) {
        evict(now);
        return m_stamps.size();
    }

private:
    void evict(std::uint64_t now) {
        while (!m_stamps.empty() && now - m_stamps.front() > m_span) {
            m_stamps.pop_front();
        }
    }

    static constexpr std::size_t kMaxSamples = 4096;
    std::uint64_t             m_span;
    std::deque<std::uint64_t> m_stamps;
};

// ---------------------------------------------------------------------------
class StatefulDetector {
public:
    explicit StatefulDetector(const Config& cfg) 
        : m_cfg(cfg),
          m_requests(cfg.windowNs),
          m_nrc35(cfg.windowNs),
          m_nrc36(cfg.windowNs) {}

    Verdict feed(const can_frame& f, std::uint64_t nowNs);

private:
    // 重放表项：O(1) 状态，不做全量历史
    struct ReplayEntry {
        bool          used     = false;
        bool          periodic = false;   // 周期性帧豁免标记

        std::uint32_t id         = 0;
        std::uint64_t hash       = 0;     // 当前重复报文的指纹
        std::uint64_t windowStart = 0;
        std::uint32_t count      = 0;

        // Welford 在线估计到达间隔的均值与方差，用于判定"周期性帧"
        std::uint64_t lastSeen = 0;
        double        mean     = 0.0;
        double        m2       = 0.0;
        std::uint32_t samples  = 0;
    };

    static constexpr std::size_t kMaxSlots = 64;

    bool        feedUds(const can_frame& f, std::uint64_t now, Verdict& v);
    void        feedReplay(const can_frame& f, std::uint64_t now, Verdict& v);
    ReplayEntry* slotFor(std::uint32_t id, std::uint64_t now);
    static std::uint64_t hashFrame(const can_frame& f);

    Config      m_cfg;
    TimeWindow  m_requests;
    TimeWindow  m_nrc35;
    TimeWindow  m_nrc36;

    std::array<ReplayEntry, kMaxSlots> m_replay{};
};

// ---------------------------------------------------------------------------
inline std::uint64_t StatefulDetector::hashFrame(const can_frame& f) {
    // FNV-1a：只覆盖真实有效的字节（dlc 之外的 data 是脏的）
    std::uint64_t h = 14695981039346656037ull;
    auto mix = [&h] (std::uint8_t b) {
        h ^= b;
        h *= 1099511628211ull;
    };

    mix(static_cast<std::uint8_t>(f.can_id));
    mix(static_cast<std::uint8_t>(f.can_id >> 8));
    mix(static_cast<std::uint8_t>(f.can_id >> 16));
    mix(static_cast<std::uint8_t>(f.can_id >> 24));
    mix(f.can_dlc);

    const std::uint8_t dlc = (f.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : f.can_dlc;
    for (std::uint8_t i = 0; i < dlc; ++i) mix(f.data[i]);

    return h;
}

inline StatefulDetector::ReplayEntry*
StatefulDetector::slotFor(std::uint32_t id, std::uint64_t now) {
    constexpr std::size_t N = kMaxSlots;
    const std::size_t start = id % N;

    std::size_t victim = start;
    for (std::size_t i = 0; i < N; ++i) {
        ReplayEntry& e = m_replay[(start + i) % N];

        if (e.used) {
            if (e.id == id) return &e;
            if (e.lastSeen < m_replay[victim].lastSeen) victim = (start + i) % N;
        } else {
            e = ReplayEntry{};
            e.used     = true;
            e.id       = id;
            e.lastSeen = now;
            return &e;
        }
    }

    // 表满：淘汰最久未见的一条，保证内存与查找时间恒定
    ReplayEntry& e = m_replay[victim];
    e = ReplayEntry{};
    e.used     = true;
    e.id       = id;
    e.lastSeen = now;
    return &e;
}

// ---------------------------------------------------------------------------
// UDS 27 状态机
//   [len, 0x27, sub]              → 请求，入窗
//   [len, 0x7F, 0x27, nrc]        → 负响应，入窗
//   [len, 0x67, 0x27]             → 正响应，结合请求窗口判定"已被攻破"
// ---------------------------------------------------------------------------
inline bool StatefulDetector::feedUds(const can_frame& f,
                                      std::uint64_t now,
                                      Verdict& v) {
    const std::uint32_t id  = f.can_id & CAN_EFF_MASK;
    const std::uint8_t  dlc = (f.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : f.can_dlc;
    if (dlc < 3) return false;

    const bool isReq  = (id >= m_cfg.udsReqBase  && id <= m_cfg.udsReqBase  + 7);
    const bool isResp = (id >= m_cfg.udsRespBase && id <= m_cfg.udsRespBase + 7);
    if (!isReq && !isResp) return false;

    // ISO-TP：只处理单帧。首帧/连续帧需要重组后再判定，
    // 但 0x27 请求本身只有 2~3 字节，实际总以 SF 出现。
    if ((f.data[0] & 0xF0) != 0x00) return false;
    const std::uint8_t len = f.data[0];

    // ---- 请求 ------------------------------------------------------------
    if (isReq) {
        if (len < 2 || f.data[1] != 0x27) return false;

        v.udsRequest = true;
        m_requests.push(now);
        const std::size_t n = m_requests.size(now);

        if (n >= m_cfg.reqThreshold) {
            const bool nrcOk = !m_cfg.requireNrc ||
                               m_nrc35.size(now) >= m_cfg.nrcThreshold ||
                               m_nrc36.size(now) >= 1;
            if (nrcOk) {
                v.alert      = true;
                v.event.kind = ipc::AlertKind::Bruteforce;
                v.event.id   = id;
                v.event.count = static_cast<std::uint32_t>(n);
            }
        }
        return false;   // 请求帧不参与重放判定
    }

    // ---- 负响应 ----------------------------------------------------------
    // [03, 7F, 27, 35] 需要 dlc >= 4，否则 data[3] 是未定义的填充字节
    if (dlc >= 4 && len >= 3 && f.data[1] == 0x7F && f.data[2] == 0x27) {
        const std::uint8_t nrc = f.data[3];
        if (nrc == 0x35)      m_nrc35.push(now);
        else if (nrc == 0x36) m_nrc36.push(now);
        else                  return false;

        // 负响应到达这一刻才做判定：比只在请求时判定快一帧
        const std::size_t n = m_requests.size(now);
        if (n >= m_cfg.reqThreshold) {
            v.alert      = true;
            v.event.kind = ipc::AlertKind::Bruteforce;
            v.event.id   = id;
            v.event.count = static_cast<std::uint32_t>(n);
        }
        return false;
    }

    // ---- 正响应：0x67 0x27 -----------------------------------------------
    if (len >= 2 && f.data[1] == 0x67 && f.data[2] == 0x27) {
        const std::size_t n = m_requests.size(now);
        if (n >= m_cfg.reqThreshold) {
            v.alert      = true;
            v.event.kind = ipc::AlertKind::UnauthorizedUnlock;
            v.event.id   = id;
            v.event.count = static_cast<std::uint32_t>(n);
        }
        return false;
    }

    return false;
}

// ---------------------------------------------------------------------------
// 重放检测
//
// 关键难点：CAN 上大量报文本身就是"周期 + 内容不变"（10 ms 的车速帧），
// 朴素地统计"相同报文重复 N 次"会把整条总线判成重放。
//
// 处理办法：用 Welford 在线估计每个 ID 的到达间隔均值/方差，
// 变异系数（stddev/mean）足够小就标记为周期性帧，永久豁免。
// 这牺牲了对"周期性帧重放"的检测能力——那需要协议级计数器，见文末说明。
// ---------------------------------------------------------------------------
inline void StatefulDetector::feedReplay(const can_frame& f,
                                         std::uint64_t now,
                                         Verdict& v) {
    const std::uint32_t id = f.can_id & CAN_EFF_MASK;
    if (id >= m_cfg.udsReqBase && id <= m_cfg.udsRespBase + 7) return;  // UDS 已单独处理

    ReplayEntry* e = slotFor(id, now);
    if (e == nullptr) return;

    // ---- 周期性估计 ------------------------------------------------------
    if (e->lastSeen != 0 && now > e->lastSeen) {
        const double dt = static_cast<double>(now - e->lastSeen);
        e->samples += 1;
        const double delta = dt - e->mean;
        e->mean += delta / static_cast<double>(e->samples);
        e->m2   += delta * (dt - e->mean);

        if (e->samples >= 32) {
            const double var = e->m2 / static_cast<double>(e->samples - 1);
            const double cv  = (e->mean > 0.0) ? std::sqrt(var) / e->mean : 1.0;
            e->periodic = (cv < 0.15);
        }
    }
    e->lastSeen = now;

    // 学习期：至少攒够 32 个间隔样本，才允许判定。
    // 否则一个 10 ms 周期帧在头 80 ms 就会被判成"重放"，整条总线全是误报。
    if (e->samples < 32) return;
    if (e->periodic) return;

    // ---- 相同报文计数 ----------------------------------------------------
    const std::uint64_t h = hashFrame(f);

    if (h != e->hash || now - e->windowStart > m_cfg.replayWindowNs) {
        e->hash        = h;
        e->windowStart = now;
        e->count       = 1;
        return;
    }

    if (++e->count == m_cfg.replayThreshold) {
        v.alert       = true;
        v.event.kind  = ipc::AlertKind::Replay;
        v.event.id    = id;
        v.event.count = e->count;
    }
}

// ---------------------------------------------------------------------------
inline Verdict StatefulDetector::feed(const can_frame& f, std::uint64_t nowNs) {
    Verdict v;

    // 错误帧与远程帧不参与行为分析；扩展帧保留（用 29 位掩码后统一比较）
    if (f.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) return v;

    const std::uint32_t id = f.can_id & CAN_EFF_MASK;
    if (id >= m_cfg.udsReqBase && id <= m_cfg.udsRespBase + 7) {
        feedUds(f, nowNs, v);
        return v;
    }

    feedReplay(f, nowNs, v);
    return v;
}

}  // namespace detection
