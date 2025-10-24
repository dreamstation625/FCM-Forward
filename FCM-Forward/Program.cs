// dotnet 8
using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

var cfg = ForwarderConfig.Load("appsettings.json");
var forwarders = new List<PortForwarder>();

foreach (var r in cfg.Routes)
{
    var pf = new PortForwarder(r);
    await pf.StartAsync(cts.Token);
    forwarders.Add(pf);
    Console.WriteLine($"[LISTEN] {r.Name} {r.ListenIp}:{r.ListenPort}  MirrorSNI={r.MirrorSni} MirrorPort={r.MirrorPort}");
}

Console.WriteLine("Running. Press Ctrl+C to stop.");
try { await Task.Delay(Timeout.Infinite, cts.Token); } catch { }
Console.WriteLine("Stopping...");
await Task.WhenAll(forwarders.Select(f => f.StopAsync()));


// --------------------------- Config ---------------------------
public sealed class ForwarderConfig
{
    public required List<Route> Routes { get; init; }

    public sealed class Route
    {
        public required string Name { get; init; }
        public string ListenIp { get; init; } = "0.0.0.0";
        public required int ListenPort { get; init; }

        public bool MirrorSni { get; init; } = true;  // 使用客户端 SNI 作为上游主机
        public bool MirrorPort { get; init; } = true; // 上游端口 = 本地监听端口
        public int? UpstreamPort { get; init; }       // 若不镜像端口，可指定上游端口
        public string? DefaultUpstreamHost { get; init; } // 无/非法 SNI 时兜底

        public string[]? AllowedHosts { get; init; }     // 允许的具体主机名
        public string[]? AllowedSuffixes { get; init; }  // 允许的后缀（google.com 等）
        public bool RejectIfNoValidSni { get; init; } = false;

        public bool TcpKeepAlive { get; init; } = true;
        public bool TcpNoDelay { get; init; } = true;
        public int ReceiveBufferSize { get; init; } = 64 * 1024;
        public int SendBufferSize { get; init; } = 64 * 1024;
        public int ConnectTimeoutMs { get; init; } = 8000;
        public int IdleCloseSeconds { get; init; } = 0; // 0 表示不启用空闲关闭

        public bool TryPortFallbackTo443 { get; init; } = true; // 连接失败时尝试 443（常见放行）
    }

    public static ForwarderConfig Load(string path)
    {
        if (!File.Exists(path))
        {
            var def = new ForwarderConfig
            {
                Routes = new List<Route>
                {
                    new Route {
                        Name="fcm-443",
                        ListenPort=443,
                        MirrorSni=true,
                        MirrorPort=true,
                        AllowedSuffixes=new[]{"googleapis.com","google.com"},
                        DefaultUpstreamHost="fcm.googleapis.com"
                    },
                    new Route {
                        Name="mtalk-5228",
                        ListenPort=5228,
                        MirrorSni=true,
                        MirrorPort=true,
                        AllowedSuffixes=new[]{"google.com"},
                        DefaultUpstreamHost="mtalk.google.com",
                        TryPortFallbackTo443=true
                    },
                    new Route {
                        Name="mtalk-5229",
                        ListenPort=5229,
                        MirrorSni=true,
                        MirrorPort=true,
                        AllowedSuffixes=new[]{"google.com"},
                        DefaultUpstreamHost="mtalk.google.com",
                        TryPortFallbackTo443=true
                    },
                    new Route {
                        Name="mtalk-5230",
                        ListenPort=5230,
                        MirrorSni=true,
                        MirrorPort=true,
                        AllowedSuffixes=new[]{"google.com"},
                        DefaultUpstreamHost="mtalk.google.com",
                        TryPortFallbackTo443=true
                    },
                }
            };
            File.WriteAllText(path, JsonSerializer.Serialize(def, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"[INFO] '{path}' not found. A default one has been generated.");
            return def;
        }

        var json = File.ReadAllText(path);
        var cfg = JsonSerializer.Deserialize<ForwarderConfig>(json) ?? throw new InvalidOperationException("Invalid appsettings.json");
        if (cfg.Routes is null || cfg.Routes.Count == 0) throw new InvalidOperationException("No routes configured.");
        return cfg;
    }
}


// --------------------------- Forwarder ---------------------------
public sealed class PortForwarder
{
    private readonly ForwarderConfig.Route _route;
    private readonly TcpListener _listener;
    private readonly List<Task> _workers = new();
    private CancellationTokenSource? _linked;

    public PortForwarder(ForwarderConfig.Route route)
    {
        _route = route;
        _listener = new TcpListener(IPAddress.Parse(route.ListenIp), route.ListenPort);
    }

    public Task StartAsync(CancellationToken stopToken)
    {
        _linked = CancellationTokenSource.CreateLinkedTokenSource(stopToken);
        try
        {
            _listener.Start();
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            Console.WriteLine($"[ERROR] Cannot bind {_route.ListenIp}:{_route.ListenPort} - need root or setcap on Linux.");
            throw;
        }
        _ = AcceptLoopAsync(_linked.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        try { _listener.Stop(); } catch { }
        _linked?.Cancel();
        try { await Task.WhenAll(_workers.ToArray()); } catch { }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient? client = null;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct);
                _workers.Add(HandleClientAsync(client, ct));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[ACCEPT ERR][{_route.Name}] {ex.Message}");
                client?.Dispose();
                await Task.Delay(200, ct);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient downstream, CancellationToken parentCt)
    {
        using (downstream)
        {
            downstream.NoDelay = _route.TcpNoDelay;
            downstream.ReceiveBufferSize = _route.ReceiveBufferSize;
            downstream.SendBufferSize = _route.SendBufferSize;
            TrySetKeepAlive(downstream, _route.TcpKeepAlive);

            var dStream = downstream.GetStream();

            // 1) 预读 ClientHello，获取 SNI（不终止 TLS）
            byte[] preBuf = Array.Empty<byte>();
            string? sniHost = null;
            try
            {
                using var preReadCts = new CancellationTokenSource(4000);
                using var readLinked = CancellationTokenSource.CreateLinkedTokenSource(parentCt, preReadCts.Token);
                preBuf = await ReadClientHelloAsync(dStream, readLinked.Token);
                sniHost = TryParseSni(preBuf);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HELLO READ FAIL][{_route.Name}] {ex.Message}");
            }

            // 2) 决定目标 host/port（SNI → 白名单校验 → 兜底）
            var targetHost = ResolveTargetHost(sniHost);
            if (string.IsNullOrWhiteSpace(targetHost))
            {
                Console.WriteLine($"[DROP][{_route.Name}] No valid target host (SNI={sniHost ?? "null"})");
                return;
            }

            var listenPort = ((IPEndPoint)downstream.Client.LocalEndPoint!).Port;
            var targetPort = _route.MirrorPort ? listenPort : (_route.UpstreamPort ?? listenPort);

            // 3) 连接上游（关键：每个尝试都 new TcpClient；失败就丢弃）
            var hostCandidates = new List<(string host, int port)> { (targetHost, targetPort) };
            if (_route.TryPortFallbackTo443 && targetPort != 443) hostCandidates.Add((targetHost, 443));
            if (!string.IsNullOrWhiteSpace(_route.DefaultUpstreamHost) &&
                !string.Equals(_route.DefaultUpstreamHost, targetHost, StringComparison.OrdinalIgnoreCase))
            {
                hostCandidates.Add((_route.DefaultUpstreamHost!, targetPort));
                if (_route.TryPortFallbackTo443 && targetPort != 443) hostCandidates.Add((_route.DefaultUpstreamHost!, 443));
            }

            using var connectCts = new CancellationTokenSource(_route.ConnectTimeoutMs);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(parentCt, connectCts.Token);

            var upstream = await ConnectUpstreamAsync(
                hostCandidates,
                _route.TcpNoDelay,
                _route.TcpKeepAlive,
                _route.ReceiveBufferSize,
                _route.SendBufferSize,
                linked.Token);

            if (upstream is null)
            {
                Console.WriteLine($"[ABORT][{_route.Name}] All upstreams failed. SNI={sniHost ?? "n/a"}");
                return;
            }

            using (upstream)
            {
                var uStream = upstream.GetStream();

                // 把预读到的 ClientHello 转发给上游
                if (preBuf.Length > 0)
                {
                    try { await uStream.WriteAsync(preBuf.AsMemory(), parentCt); await uStream.FlushAsync(parentCt); }
                    catch (Exception ex) { Console.WriteLine($"[PREWRITE FAIL][{_route.Name}] {ex.Message}"); return; }
                }

                Console.WriteLine($"[OK][{_route.Name}] {Remote(downstream)} -> {Remote(upstream)} host={targetHost} port={((IPEndPoint)upstream.Client.RemoteEndPoint!).Port} SNI={sniHost ?? "n/a"}");

                // 4) 双向转发
                using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(parentCt);
                var t1 = PumpAsync(dStream, uStream, $"C->S:{_route.Name}", relayCts.Token, _route.IdleCloseSeconds);
                var t2 = PumpAsync(uStream, dStream, $"S->C:{_route.Name}", relayCts.Token, _route.IdleCloseSeconds);

                await Task.WhenAny(t1, t2);
                relayCts.Cancel();
                try { await Task.WhenAll(t1, t2); } catch { }
            }
        }
    }

    private string? ResolveTargetHost(string? sni)
    {
        bool IsAllowed(string host)
        {
            host = host.TrimEnd('.').ToLowerInvariant();
            if (_route.AllowedHosts is { Length: > 0 })
            {
                if (_route.AllowedHosts.Any(h => string.Equals(h.TrimEnd('.').ToLowerInvariant(), host, StringComparison.Ordinal)))
                    return true;
            }
            if (_route.AllowedSuffixes is { Length: > 0 })
            {
                foreach (var s in _route.AllowedSuffixes)
                {
                    var t = s.Trim('.').ToLowerInvariant();
                    if (host == t || host.EndsWith("." + t, StringComparison.Ordinal))
                        return true;
                }
                return false;
            }
            return true; // 无白名单则放行
        }

        if (_route.MirrorSni && !string.IsNullOrWhiteSpace(sni))
        {
            var h = sni.TrimEnd('.').ToLowerInvariant();
            if (IsAllowed(h)) return h;
            if (_route.RejectIfNoValidSni) return null;
        }

        return _route.DefaultUpstreamHost;
    }

    private static async Task<TcpClient?> ConnectUpstreamAsync(
        IEnumerable<(string host, int port)> targets,
        bool noDelay, bool keepAlive, int rcvBuf, int sndBuf, CancellationToken ct)
    {
        foreach (var (host, port) in targets)
        {
            IPAddress[] addrs;
            try
            {
                addrs = await Dns.GetHostAddressesAsync(host, ct);
                // IPv4 优先，很多环境 v6 不通
                addrs = addrs.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DNS FAIL] {host} -> {ex.Message}");
                continue;
            }

            foreach (var ip in addrs)
            {
                var cli = new TcpClient(ip.AddressFamily);
                try
                {
                    cli.NoDelay = noDelay;
                    cli.ReceiveBufferSize = rcvBuf;
                    cli.SendBufferSize = sndBuf;
                    TrySetKeepAlive(cli, keepAlive);

                    await cli.ConnectAsync(ip, port, ct);
                    Console.WriteLine($"[CONNECT OK] {host} ({ip}) :{port}");
                    return cli;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[CONNECT FAIL] {host} ({ip}) :{port} -> {ex.Message}");
                    try { cli.Dispose(); } catch { }
                    // 试下一个 IP
                }
            }
            // 试下一个 host/port 组合
        }
        return null;
    }

    private static async Task PumpAsync(Stream src, Stream dst, string tag, CancellationToken ct, int idleCloseSeconds)
    {
        var buf = new byte[64 * 1024];
        while (!ct.IsCancellationRequested)
        {
            int read;
            try
            {
                var readTask = src.ReadAsync(buf.AsMemory(), ct).AsTask();
                if (idleCloseSeconds > 0)
                {
                    var timeoutTask = Task.Delay(TimeSpan.FromSeconds(idleCloseSeconds), ct);
                    var finished = await Task.WhenAny(readTask, timeoutTask);
                    if (finished == timeoutTask)
                    {
                        Console.WriteLine($"[IDLE CLOSE] {tag} {idleCloseSeconds}s");
                        break;
                    }
                }
                read = await readTask;
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[READ ERR] {tag}: {ex.Message}"); break; }

            if (read == 0) break;

            try
            {
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
                await dst.FlushAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[WRITE ERR] {tag}: {ex.Message}"); break; }
        }
        try { dst.Flush(); } catch { }
    }

    private static void TrySetKeepAlive(TcpClient c, bool on)
    {
        try { c.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, on); } catch { }
    }

    private static string Remote(TcpClient c)
    {
        try { return ((IPEndPoint)c.Client.RemoteEndPoint!).ToString(); } catch { return "?"; }
    }

    // ------------- ClientHello 预读与 SNI 解析 -------------
    private static async Task<byte[]> ReadClientHelloAsync(NetworkStream ns, CancellationToken ct)
    {
        var buf = new ArrayBufferWriter<byte>(16 * 1024);

        var header = new byte[5];
        await FillAsync(ns, header, ct);
        buf.Write(header);

        if (header[0] != 0x16) // 非 TLS Handshake
            return buf.WrittenSpan.ToArray();

        var recLen = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
        if (recLen > 0)
        {
            var payload = new byte[recLen];
            await FillAsync(ns, payload, ct);
            buf.Write(payload);
        }

        // 尝试把后续可用数据读一些（最多 16KB）
        ns.ReadTimeout = 3000;
        while (buf.WrittenCount < 16 * 1024 && ns.DataAvailable)
        {
            var tmp = new byte[2048];
            var n = await ns.ReadAsync(tmp, ct);
            if (n <= 0) break;
            buf.Write(tmp.AsSpan(0, n));
        }

        return buf.WrittenSpan.ToArray();
    }

    private static async Task FillAsync(Stream s, byte[] target, CancellationToken ct)
    {
        int off = 0;
        while (off < target.Length)
        {
            var n = await s.ReadAsync(target.AsMemory(off, target.Length - off), ct);
            if (n <= 0) throw new IOException("Unexpected EOF while reading");
            off += n;
        }
    }

    private static string? TryParseSni(byte[] tlsRecord)
    {
        try
        {
            var span = tlsRecord.AsSpan();
            if (span.Length < 5 || span[0] != 0x16) return null;
            var recLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(3, 2));
            if (span.Length < 5 + recLen) return null;
            var body = span.Slice(5, recLen);

            if (body.Length < 4 || body[0] != 0x01) return null; // ClientHello
            var hsLen = (body[1] << 16) | (body[2] << 8) | body[3];
            if (body.Length < 4 + hsLen) return null;
            var p = body.Slice(4, hsLen);

            if (p.Length < 34) return null; // version(2)+random(32)
            p = p.Slice(34);

            if (p.Length < 1) return null; // session id
            var sidLen = p[0];
            p = p.Slice(1);
            if (p.Length < sidLen) return null;
            p = p.Slice(sidLen);

            if (p.Length < 2) return null; // cipher suites
            var csLen = BinaryPrimitives.ReadUInt16BigEndian(p.Slice(0, 2));
            p = p.Slice(2);
            if (p.Length < csLen) return null;
            p = p.Slice(csLen);

            if (p.Length < 1) return null; // compression methods
            var compLen = p[0];
            p = p.Slice(1);
            if (p.Length < compLen) return null;
            p = p.Slice(compLen);

            if (p.Length < 2) return null; // extensions
            var extLen = BinaryPrimitives.ReadUInt16BigEndian(p.Slice(0, 2));
            p = p.Slice(2);
            if (p.Length < extLen) return null;
            var exts = p.Slice(0, extLen);

            while (exts.Length >= 4)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(exts.Slice(0, 2));
                var len = BinaryPrimitives.ReadUInt16BigEndian(exts.Slice(2, 2));
                exts = exts.Slice(4);
                if (exts.Length < len) break;

                if (type == 0x0000) // server_name
                {
                    var sn = exts.Slice(0, len);
                    if (sn.Length < 2) break;
                    var listLen = BinaryPrimitives.ReadUInt16BigEndian(sn.Slice(0, 2));
                    var q = sn.Slice(2);
                    if (q.Length < listLen) break;

                    while (q.Length >= 3)
                    {
                        var nameType = q[0];
                        var nameLen = BinaryPrimitives.ReadUInt16BigEndian(q.Slice(1, 2));
                        q = q.Slice(3);
                        if (q.Length < nameLen) break;

                        if (nameType == 0x00) // host_name
                        {
                            var host = Encoding.ASCII.GetString(q.Slice(0, nameLen));
                            host = host.TrimEnd('.').ToLowerInvariant();
                            return host;
                        }
                        q = q.Slice(nameLen);
                    }
                }
                exts = exts.Slice(len);
            }
            return null;
        }
        catch { return null; }
    }
}
