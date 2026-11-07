from flask import Flask, request, jsonify, render_template_string
import datetime

app = Flask(__name__)

# 内存里保存最新的统计数据
stats_data = {
    "dropped": 0, "normal": 0, "bad": 0, 
    "blacklisted": 0, "bruteforce": 0,
    "last_update": "等待 C++ 数据传输...",
    "alert_log": [] # 存放最近的报警信息
}

# 这是一个赛博朋克风的网页大屏 (纯 HTML+CSS+JS)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Car Security Dashboard</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: 'Courier New', Courier, monospace; text-align: center; }
        h1 { color: #58a6ff; text-shadow: 0 0 10px #58a6ff; }
        .container { display: flex; justify-content: center; flex-wrap: wrap; gap: 20px; margin-top: 30px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; width: 200px; box-shadow: 0 0 15px rgba(88, 166, 255, 0.2); }
        .card h2 { margin: 0; font-size: 16px; color: #8b949e; }
        .card .num { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .normal { color: #3fb950; } .bad { color: #d29922; } .danger { color: #f85149; text-shadow: 0 0 10px #f85149; }
        #alert-box { margin-top: 40px; padding: 20px; border: 1px solid #f85149; background: rgba(248, 81, 73, 0.1); border-radius: 8px; display: none; }
        #log-list { text-align: left; max-width: 800px; margin: 20px auto; color: #8b949e; }
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
        <div class="card"><h2>队列丢弃</h2><div class="num bad" id="dropped">0</div></div>
    </div>

    <div id="log-list"></div>

    <script>
        function fetchData() {
            fetch('/api/data').then(res => res.json()).then(data => {
                document.getElementById('update-time').innerText = "最后更新: " + data.last_update;
                document.getElementById('normal').innerText = data.normal;
                document.getElementById('bad').innerText = data.bad;
                document.getElementById('blacklisted').innerText = data.blacklisted;
                document.getElementById('bruteforce').innerText = data.bruteforce;
                document.getElementById('dropped').innerText = data.dropped;
                
                // 如果有攻击，闪烁红框
                if (data.blacklisted > 0 || data.bruteforce > 0 || data.bad > 0) {
                    document.getElementById('alert-box').style.display = 'block';
                    document.getElementById('alert-box').style.opacity = (Math.sin(Date.now() / 200) + 1) / 2; // 呼吸闪烁效果
                } else {
                    document.getElementById('alert-box').style.display = 'none';
                }

                // 更新日志列表
                let logHtml = "<h3>最近告警记录：</h3>";
                data.alert_log.forEach(log => { logHtml += `<p>${log}</p >`; });
                document.getElementById('log-list').innerHTML = logHtml;
            });
        }
        setInterval(fetchData, 1000); // 每秒刷新一次
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

# C++ 发数据过来的接口
@app.route('/api/report', methods=['POST'])
def report():
    data = request.json
    stats_data["normal"] = data.get("normal", 0)
    stats_data["bad"] = data.get("bad", 0)
    stats_data["blacklisted"] = data.get("blacklisted", 0)
    stats_data["bruteforce"] = data.get("bruteforce", 0)
    stats_data["dropped"] = data.get("dropped", 0)
    stats_data["last_update"] = datetime.datetime.now().strftime("%H:%M:%S")
    
    # 如果 C++ 传来了具体的攻击日志（比如 AI 说的话），就存下来
    if "log" in data and data["log"]:
        stats_data["alert_log"].insert(0, f"[{stats_data['last_update']}] {data['log']}")
        if len(stats_data["alert_log"]) > 5: # 只保留最近 5 条
            stats_data["alert_log"].pop()

    return jsonify({"status": "ok"})

# 前端页面拉取数据的接口
@app.route('/api/data')
def get_data():
    return jsonify(stats_data)

if __name__ == '__main__':
    print("Web 服务器启动，请用浏览器访问 http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)