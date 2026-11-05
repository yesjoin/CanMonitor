import subprocess
import time

print("[ECU] 汽车发动机控制单元已启动，等待诊断...")

while True:
    try:
        # 每次只抓取发给 0x7E0 的报文
        res = subprocess.run(["candump", "-n", "1", "vcan0,7E0:7FF"], capture_output=True, text=True, timeout=10)
        line = res.stdout.strip()
        
        if not line:
            continue

        print(f"[ECU 收到原始数据] {line}")

        if "27 01" in line:
            seed = 0x11223344
            print(f"[ECU] 收到种子请求，下发种子: {hex(seed)}")
            # 👇 注意这里的格式：08X
            send_cmd = f"7E8#6701{seed:08X}"
            print(f"[ECU 发送回复] {send_cmd}")
            subprocess.run(["cansend", "vcan0", send_cmd])
            
        elif "27 02" in line:
            print("[ECU] 收到密钥尝试，正在验证...")
            # 模拟验证成功
            subprocess.run(["cansend", "vcan0", "7E8#6702"])
            print("[ECU] 验证通过！安全访问已解除！(被攻破)")
            
    except subprocess.TimeoutExpired:
        pass