import subprocess

def run_can_checker():
    print("[Python] 正在自动启动 C++ CAN 报文解析工具...")
    
    # 调用 C++ 程序，并抓取输出
    result = subprocess.run(["./can_frame"], capture_output=True, text=True)
    
    output_text = result.stdout
    print("[Python] C++ 程序运行完毕，正在分析输出结果...\n")
    
    # 检查有没有警告
    if "[警告" in output_text:
        print("🚨 [自动化告警] 发现异常报文！")
        
        # 提取报错详情
        for line in output_text.split("\n"):
            if "[警告" in line:
                print(f"   -> 异常详情: {line.strip()}")
                
        print("\n[Python] 准备触发 ComfyUI 自动生成告警图片（留到以后实现）...")
    else:
        print("✅ [自动化巡检] 一切正常，未发现异常报文。")

if __name__ == "__main__":
    run_can_checker()
