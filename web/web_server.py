#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web_server.py —— CAN 安全网关遥测大屏（加固版）

对应 ARCHITECTURE.md 中的 Web 层问题：
  W-01  默认只绑定 127.0.0.1；远端上报必须携带 X-API-Key
  W-02  前端不再使用 innerHTML，全部 textContent / createElement
  W-03  全局状态加锁，读取时返回快照，消除 insert/pop 竞态
  W-04  request.get_json(silent=True)，畸形请求不再 500
  W-05  所有计数字段强制转 int 并钳制范围
  W-06  日志长度上限 500 字符、条数上限 5
  W-08  CSP(nonce) / nosniff / frame-ancestors 等响应头
  W-09  模板常量 + Jinja 缓存，不再每请求重编译
新增：
  +  last_update_ts —— 前端据此识别"数据陈旧"，网关挂了不再假装正常
  +  轮询改为递归 setTimeout，慢响应时不会堆积请求
"""

import datetime
import hmac
import os
import secrets
import threading

from flask import Flask, jsonify, make_response, render_template_string, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# 全局状态：所有读写都在 _LOCK 内完成
# ---------------------------------------------------------------------------
_LOCK = threading.Lock()

MAX_LOG_ENTRIES = 5
MAX_LOG_CHARS = 500
MAX_COUNT = 10 ** 9

_COUNT_KEYS = ("normal", "bad", "blacklisted", "bruteforce", "dropped")

_STATE = {
    "normal": 0,
    "bad": 0,
    "blacklisted": 0,
    "bruteforce": 0,
    "dropped": 0,
    "last_update": "等待 C++ 数据传输...",
    "last_update_ts": 0.0,          # Unix 时间戳，供前端判断是否过期
    "alert_log": [],
}


def _as_count(value):
    """把任意输入钳制成 [0, MAX_COUNT] 的整数，类型错误一律归零。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    if n < 0:
        return 0
    return n if n < MAX_COUNT else MAX_COUNT


def _report_authorized():
    """
    上报鉴权策略：
      · 配置了 REPORT_TOKEN  -> 必须带匹配的 X-API-Key（常量时间比较）
      · 未配置               -> 只接受来自本机（127.0.0.1 / ::1）的上报
    默认部署形态是 C++ 与 Flask 同机，因此不加配置也能正常工作。
    """
    expected = os.environ.get("REPORT_TOKEN", "")
    if expected:
        return hmac.compare_digest(request.headers.get("X-API-Key", ""), expected)
    return request.remote_addr in ("127.0.0.1", "::1")


# ---------------------------------------------------------------------------
# 页面模板（常量，Jinja 只会编译一次）
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Car Security Dashboard</title>
<style>
    body { background-color: #0d1117; color: #c9d1d9;
           font-family: 'Courier New', Courier, monospace; text-align: center; }
    h1 { color: #58a6ff; text-shadow: 0 0 10px #58a6ff; }
    #update-time.offline { color: #f85149; }
    .container { display: flex; justify-content: center; flex-wrap: wrap;
                 gap: 20px; margin-top: 30px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 20px; width: 200px;
            box-shadow: 0 0 15px rgba(88, 166, 255, 0.2); }
    .card h2 { margin: 0; font-size: 16px; color: #8b949e; }
    .card .num { font-size: 36px; font-weight: bold; margin: 10px 0; }
    .normal { color: #3fb950; }
    .bad { color: #d29922; }
    .danger { color: #f85149; text-shadow: 0 0 10px #f85149; }
    #alert-box { margin-top: 40px; padding: 20px; border: 1px solid #f85149;
                 background: rgba(248, 81, 73, 0.1); border-radius: 8px;
                 display: none; }
    #alert-box.visible { display: block; animation: alertPulse 1s ease-in-out infinite; }
    @keyframes alertPulse { 0%, 100% { opacity: .30; } 50% { opacity: 1; } }
    #log-list { text-align: left; max-width: 800px; margin: 20px auto; color: #8b949e; }
    #log-list p { margin: 6px 0; word-break: break-all; }
</style>
</head>
<body>
    <h1>🚗 车载安全网关 - 实时监控大屏</h1>
    <h3 id="update-time">等待数据...</h3>

    <div id="alert-box">
        <h2 style="color: #f85149;">🚨 警告：检测到严重攻击！</h2>
    </div>

    <div class="container">
        <div class="card"><h2>正常帧 (FPS)</h2><div class="num normal" id="normal">0</div></div>
        <div class="card"><h2>畸形报文</h2><div class="num bad" id="bad">0</div></div>
        <div class="card"><h2>黑名单拦截</h2><div class="num danger" id="blacklisted">0</div></div>
        <div class="card"><h2>UDS 爆破</h2><div class="num danger" id="bruteforce">0</div></div>
        <div class="card"><h2>队列丢弃（累计）</h2><div class="num bad" id="dropped">0</div></div>
    </div>

    <div id="log-list"></div>

<script nonce="{{ nonce }}">
(function () {
    "use strict";

    var REFRESH_MS = 1000;   // 轮询间隔
    var STALE_MS   = 3000;   // 超过这个时间没收到上报，判定为离线

    function $(id) { return document.getElementById(id); }

    function setText(id, value) {
        var el = $(id);
        if (el) el.textContent = String(value);
    }

    function clearNode(node) {
        while (node.firstChild) node.removeChild(node.firstChild);
    }

    // 用 DOM 节点构建列表：日志内容永远只当文本，不参与 HTML 解析
    function renderLogs(logs) {
        var box = $("log-list");
        if (!box) return;
        clearNode(box);

        var title = document.createElement("h3");
        title.textContent = "最近告警记录：";
        box.appendChild(title);

        if (!Array.isArray(logs) || logs.length === 0) {
            var empty = document.createElement("p");
            empty.textContent = "暂无告警";
            box.appendChild(empty);
            return;
        }

        logs.forEach(function (line) {
            var p = document.createElement("p");
            p.textContent = String(line);   // ← XSS 防线就在这一行
            box.appendChild(p);
        });
    }

    function setOnline(online, text) {
        var t = $("update-time");
        if (!t) return;
        t.classList.toggle("offline", !online);
        t.textContent = text;
    }

    function applyData(data) {
        setText("normal", data.normal);
        setText("bad", data.bad);
        setText("blacklisted", data.blacklisted);
        setText("bruteforce", data.bruteforce);
        setText("dropped", data.dropped);

        var ts = Number(data.last_update_ts) || 0;
        var online = ts > 0 && (Date.now() - ts * 1000) < STALE_MS;
        setOnline(online, online
            ? "最后更新: " + data.last_update
            : "⚠ 数据已过期 —— 网关可能已离线");

        var attacking = data.blacklisted > 0 || data.bruteforce > 0 || data.bad > 0;
        $("alert-box").classList.toggle("visible", attacking);

        renderLogs(data.alert_log);
    }

    function schedule() {
        window.setTimeout(poll, REFRESH_MS);   // 上一次结束才排下一次，不堆积
    }

    function poll() {
        fetch("/api/data", { cache: "no-store" })
            .then(function (res) {
                if (!res.ok) throw new Error("HTTP " + res.status);
                return res.json();
            })
            .then(applyData)
            .catch(function (err) {
                setOnline(false, "⚠ 无法连接监控服务: " + err.message);
            })
            .then(schedule, schedule);
    }

    poll();
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard():
    nonce = secrets.token_urlsafe(16)
    resp = make_response(render_template_string(HTML_TEMPLATE, nonce=nonce))
    # 只允许带本次 nonce 的脚本执行，内联注入的 <script> 一律不跑
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'nonce-" + nonce + "'; "
        "style-src 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return resp


@app.route("/api/report", methods=["POST"])
def report():
    if not _report_authorized():
        return jsonify({"status": "forbidden"}), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "bad request"}), 400

    now = datetime.datetime.now()

    with _LOCK:
        for key in _COUNT_KEYS:
            _STATE[key] = _as_count(data.get(key, 0))

        _STATE["last_update"] = now.strftime("%H:%M:%S")
        _STATE["last_update_ts"] = now.timestamp()

        if data.get("log"):
            text = str(data["log"])[:MAX_LOG_CHARS]
            _STATE["alert_log"].insert(0, "[" + now.strftime("%H:%M:%S") + "] " + text)
            del _STATE["alert_log"][MAX_LOG_ENTRIES:]     # 只保留最近 N 条

    return jsonify({"status": "ok"})


@app.route("/api/data")
def get_data():
    with _LOCK:
        # 在锁内做快照，避免 jsonify 序列化时后台线程正在 insert/pop
        payload = {
            "normal": _STATE["normal"],
            "bad": _STATE["bad"],
            "blacklisted": _STATE["blacklisted"],
            "bruteforce": _STATE["bruteforce"],
            "dropped": _STATE["dropped"],
            "last_update": _STATE["last_update"],
            "last_update_ts": _STATE["last_update_ts"],
            "alert_log": list(_STATE["alert_log"]),
        }

    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


if __name__ == "__main__":
    host = os.environ.get("DASH_HOST", "127.0.0.1")
    port = int(os.environ.get("DASH_PORT", "5000"))
    token_on = bool(os.environ.get("REPORT_TOKEN"))

    print("Dashboard : http://%s:%d" % (host, port))
    print("上报鉴权  : %s" % ("X-API-Key" if token_on else "仅限本机 (127.0.0.1)"))

    # 单用户看板 + 1 rps 上报，Flask 内置服务器完全够用；
    # 若要暴露到局域网，请前置 nginx + TLS，不要直接把 host 改成 0.0.0.0。
    app.run(host=host, port=port, debug=False, threaded=True)
