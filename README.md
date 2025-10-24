# FCM TCP Forwarder (.NET 8)

一个基于 **.NET 8** 编写的轻量级 **FCM / mtalk 流量透明转发器**。  
它可以在服务器上监听指定端口（如 443、5228–5230），读取客户端的 **TLS SNI** 字段，并将流量原样转发到相同的上游主机，实现 **“进入的流量是什么域名，就转发到那个域名”** 的行为。

本项目适合以下场景：
- 让服务器作为中间“中继”节点，自动识别 SNI 并透明转发；
- 不解密 TLS、不修改数据，纯 TCP 层透传，客户端与 Google 端到端加密。

---

## ✨ 功能特性

- ✅ **SNI 自动转发**：读取 TLS ClientHello 获取 Host，自动直连目标主机  
- ✅ **透明透传**：不终止 TLS，不需要证书  
- ✅ **IPv4 优先**：防止 IPv6 路由不通导致连接失败  
- ✅ **自动重试 / 端口回退**：5228–5230 连不上时可自动尝试 443  
- ✅ **白名单过滤**：仅允许 googleapis.com / google.com 域名  
- ✅ **连接保活**：支持 TCP KeepAlive，防止 NAT 空闲断线  
- ✅ **高并发异步 IO**：使用 `NetworkStream.CopyToAsync` 双向泵  
- ✅ **跨平台运行**：Windows / Linux / Debian 皆可运行  
- ✅ **systemd 支持**：可作为服务常驻后台  

---

## ⚙️ 工作原理

1. 客户端发起 TLS 握手（例如访问 `fcm.googleapis.com:443`）。  
2. 服务器收到连接，预读 TLS ClientHello，解析出 `SNI` 主机名。  
3. 根据配置校验白名单后，直连对应上游主机（同端口）。  
4. 把刚才读到的字节写给上游，然后双向转发数据。  
5. TLS 握手和应用层通讯仍是客户端 ↔ Google 的直接加密通信。

📊 程序不会持久化任何数据、不会篡改 TLS、不会解密内容。

客户端连接到这些域名时，流量会先到你的服务器 → 自动识别 SNI → 转发到真实 Google 主机。

---

## 🧰 安装与运行（Debian 12 示例）

### 1️⃣ 安装 .NET 8 SDK
```bash
sudo apt update
sudo apt install -y wget ca-certificates apt-transport-https gnupg
wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install -y dotnet-sdk-8.0
dotnet --info
```

### 2️⃣ 上传文件


### 3️⃣ 授予权限
```bash
sudo chmod u+x ./FCM-Forward
```

### 4️⃣ 运行
```bash
sudo ./FcmForwarder
```

---

## ⚙️ 配置说明（`appsettings.json`）

```json
{
  "Routes": [
    {
      "Name": "fcm-443",
      "ListenIp": "0.0.0.0",
      "ListenPort": 443,
      "MirrorSni": true,
      "MirrorPort": true,
      "AllowedSuffixes": ["googleapis.com", "google.com"],
      "DefaultUpstreamHost": "fcm.googleapis.com",
      "RejectIfNoValidSni": false
    },
    {
      "Name": "mtalk-5228",
      "ListenIp": "0.0.0.0",
      "ListenPort": 5228,
      "MirrorSni": true,
      "MirrorPort": true,
      "AllowedHosts": [
        "mtalk.google.com",
        "mtalk4.google.com",
        "alt1-mtalk.google.com",
        "alt2-mtalk.google.com",
        "alt3-mtalk.google.com",
        "alt4-mtalk.google.com",
        "alt5-mtalk.google.com",
        "alt6-mtalk.google.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com"
      ],
      "DefaultUpstreamHost": "mtalk.google.com",
      "RejectIfNoValidSni": false
    },
    {
      "Name": "mtalk-5229",
      "ListenIp": "0.0.0.0",
      "ListenPort": 5229,
      "MirrorSni": true,
      "MirrorPort": true,
      "AllowedSuffixes": ["google.com"],
      "DefaultUpstreamHost": "mtalk.google.com"
    },
    {
      "Name": "mtalk-5230",
      "ListenIp": "0.0.0.0",
      "ListenPort": 5230,
      "MirrorSni": true,
      "MirrorPort": true,
      "AllowedSuffixes": ["google.com"],
      "DefaultUpstreamHost": "mtalk.google.com"
    }
  ]
}

```

### 字段解释

| 字段 | 说明 |
|------|------|
| `ListenPort` | 本地监听端口（443、5228、5229、5230） |
| `MirrorSni` | 是否使用 SNI 主机名转发（一般设为 true） |
| `MirrorPort` | 是否镜像本地端口作为上游端口 |
| `DefaultUpstreamHost` | 当解析不到 SNI 或非法时兜底的上游主机 |
| `AllowedHosts` / `AllowedSuffixes` | 白名单过滤（安全用） |
| `TryPortFallbackTo443` | 连接失败时自动尝试 443 |
| `ConnectTimeoutMs` | 上游连接超时 |
| `IdleCloseSeconds` | 空闲关闭时间（0 表示不主动断开） |

---

## 🧾 注册 systemd 服务（可选）

```bash
sudo nano /etc/systemd/system/fcm-forwarder.service
```

内容：

```ini
[Unit]
Description=FCM TCP Forwarder (.NET)
After=network-online.target

[Service]
WorkingDirectory=/opt/fcm-forwarder
ExecStart=/opt/fcm-forwarder/FCM-Forward
Restart=always
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=DOTNET_GCServer=1

[Install]
WantedBy=multi-user.target
```

启用服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fcm-forwarder
sudo systemctl status fcm-forwarder
```

实时日志：
```bash
sudo journalctl -u fcm-forwarder -f
```

---

## 🌐 DNS 配置 / Mihomo配置

1、使用代理工具代理FCM流量时，可以添加hosts，将上述json里的host添加进去，值为部署服务器的ip，这样流量就会进入中转服务器，但是这种方式没太大必要（）

2、直连用法。如果使用的代理工具路由FCM流量，请将FCM的规则设置成直连，然后需要自己部署一台DNS服务器（AdguardHome等），添加DNS重写，然后在安卓端使用自定义DNS，设置为自己的DOT DNS。

---

## 🧠 常见问题

### ❓ 1. 为什么连接不上？
- 检查云防火墙/安全组是否放行 **443/5228–5230 出站端口**。
- `ss -lntp | grep 443` 看是否端口被占用。
- `curl https://fcm.googleapis.com` 或 `openssl s_client -connect mtalk.google.com:5228` 测试服务器出口。

### ❓ 2. 需要开启 `TcpKeepAlive` 吗？
建议开启 ✅  
防止 NAT/防火墙空闲断开。Debian 上推荐系统参数：
```bash
sudo tee /etc/sysctl.d/99-keepalive.conf <<'EOF'
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_keepalive_probes=4
EOF
sudo sysctl --system
```

### ❓ 3. 程序会读取或解密数据吗？
不会。  
它仅转发 TCP 字节流，不介入 TLS 握手，也不持久化任何内容。

### ❓ 4. 可以运行在 Windows 上吗？
可以，但监听 443 需要 **管理员权限**；推荐在 Debian 上运行更稳定。

---

## ⚙️ 优化建议

- 将服务器部署在海外或延迟低的节点（如日本/新加坡/Virginia）。  
- 调大文件句柄限制：
  ```bash
  ulimit -n 65535
  ```
- 配合 `systemd` 自动重启，保持稳定。  

---

