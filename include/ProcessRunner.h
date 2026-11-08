#pragma once
// ============================================================================
// ProcessRunner.h —— 不经过 shell 的子进程执行器
//
// 为什么必须替换 system() / popen()：
//   1. system() 把整条字符串交给 /bin/sh 解析，任何来自外部的字符都是注入面。
//      即使做了"过滤引号"，$()、反引号、反斜杠、换行仍然能逃逸。
//   2. system() 无法设置超时：子进程一挂死，调用线程就永远回不来。
//   3. popen() 只捕获 stdout，无法区分"正常退出 / 超时 / 被信号杀死"。
//
// 本实现：
//   · argv 数组直接交给 posix_spawnp，参数不经过任何解析器；
//   · 子进程独立成组（POSIX_SPAWN_SETPGROUP），超时时整组 SIGKILL，
//     不会留下孤儿进程；
//   · 用 poll 实现截止时间，管道同时充当"子进程还活着"的信号，
//     顺便避免了子进程写满管道导致的死锁；
//   · 返回值区分 spawn 失败 / 超时 / 正常退出 / 被信号杀死。
//
// 用法：
//   auto r = ProcessRunner::run({"curl", "-s", url, "-d", body},
//                               std::chrono::seconds(2));
//   if (r.ok()) { ... r.out ... }
// ============================================================================

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;

class ProcessRunner {
public:
    struct Result {
        bool        spawned   = false;   // posix_spawnp 是否成功
        int         errnoVal  = 0;       // spawn 失败时的 errno
        bool        timedOut  = false;   // 是否被我们的截止时间杀掉
        bool        exited    = false;   // 是否正常退出（WIFEXITED）
        int         exitCode  = -1;      // 正常退出时的退出码
        bool        signaled  = false;   // 是否被信号杀死（WIFSIGNALED）
        int         termSig   = 0;       // 杀死它的信号
        bool        truncated = false;   // 输出超过 maxOutput 被截断
        std::string out;                 // 捕获的 stdout

        bool ok() const {
            return spawned && !timedOut && exited && exitCode == 0;
        }
    };

    // args[0] 是程序名或绝对路径，其余是原样传递的参数。
    // 参数里出现空格、引号、分号、$()、反引号都不会被解释——它们只是字节。
    static Result run(const std::vector<std::string>& args,
                      std::chrono::milliseconds timeout,
                      std::size_t maxOutput = 1u << 20,
                      bool keepOutput = true);
};

inline ProcessRunner::Result ProcessRunner::run(
        const std::vector<std::string>& args,
        std::chrono::milliseconds timeout,
        std::size_t maxOutput,
        bool keepOutput)
{
    Result r;
    if (args.empty() || args.front().empty()) return r;

    int fds[2] = {-1, -1};
    if (::pipe2(fds, O_CLOEXEC) != 0) {
        r.errnoVal = errno;
        return r;
    }

    // ---- 子进程的文件描述符布局 -------------------------------------------
    // stdout -> 管道写端；stdin -> /dev/null；stderr -> /dev/null
    posix_spawn_file_actions_t fa;
    const int faRc = ::posix_spawn_file_actions_init(&fa);
    if (faRc != 0) {                       // 这些接口直接返回错误码，不设 errno
        ::close(fds[0]); ::close(fds[1]);
        r.errnoVal = faRc;
        return r;
    }
    ::posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    ::posix_spawn_file_actions_addclose(&fa, fds[0]);
    ::posix_spawn_file_actions_addopen(&fa, STDIN_FILENO,  "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    // ---- 让子进程成为独立进程组组长 ---------------------------------------
    // 这样超时时 kill(-pid) 能覆盖它 fork 出来的所有后代（例如 shell 包装器）。
    posix_spawnattr_t attr;
    ::posix_spawnattr_init(&attr);
    ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    ::posix_spawnattr_setpgroup(&attr, 0);

    // posix_spawn 要求 char* 数组，但不会修改内容
    std::vector<std::string> store(args);
    std::vector<char*> argv;
    argv.reserve(store.size() + 1);
    for (auto& s : store) argv.push_back(&s[0]);
    argv.push_back(nullptr);

    pid_t pid = -1;
    const int rc = ::posix_spawnp(&pid, argv[0], &fa, &attr, argv.data(), environ);

    ::posix_spawn_file_actions_destroy(&fa);
    ::posix_spawnattr_destroy(&attr);
    ::close(fds[1]);                       // 父进程只保留读端

    if (rc != 0) {
        ::close(fds[0]);
        r.errnoVal = rc;
        return r;
    }
    r.spawned = true;

    // ---- 读输出，同时充当截止时间 -----------------------------------------
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    char buf[8192];
    bool eof = false;

    while (!eof) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { r.timedOut = true; break; }

        const auto leftMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                deadline - now).count();
        pollfd pfd{};
        pfd.fd     = fds[0];
        pfd.events = POLLIN;

        const int pr = ::poll(&pfd, 1, static_cast<int>(leftMs));
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) { r.timedOut = true; break; }   // 超时

        const ssize_t n = ::read(fds[0], buf, sizeof buf);
        if (n > 0) {
            if (keepOutput) {
                const std::size_t got  = static_cast<std::size_t>(n);
                const std::size_t room = (r.out.size() < maxOutput)
                                       ? (maxOutput - r.out.size()) : 0;
                if (room > 0) r.out.append(buf, std::min(got, room));
                if (got > room) r.truncated = true;
            }
        } else if (n == 0) {
            eof = true;                              // 子进程关闭了 stdout
        } else if (errno != EINTR && errno != EAGAIN) {
            break;
        }
    }

    ::close(fds[0]);

    if (r.timedOut) {
        // 整组杀：子进程是组长，-pid 覆盖它的全部后代
        if (::kill(-pid, SIGKILL) != 0) ::kill(pid, SIGKILL);
    }

    int status = 0;
    pid_t w;
    do {
        w = ::waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);

    if (w == pid) {
        if (WIFEXITED(status)) {
            r.exited   = true;
            r.exitCode = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            r.signaled = true;
            r.termSig  = WTERMSIG(status);
        }
    }
    return r;
}
