package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"warp/registration"
	"warp/tunnel"
)

// defaultStateFile holds the registration: keys, token, edge endpoint and the
// edge public key that the connection is pinned to.
const defaultStateFile = "reg.json"

// usage replaces the flag package's default listing. That listing sorts
// alphabetically, which puts the destructive -del first and buries -l, and it
// has nowhere to put the two caveats a new user most needs to know: UDP does not
// traverse the tunnel, and the default listen address is world-reachable with no
// authentication.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `warp —— Cloudflare WARP 客户端（MASQUE over QUIC/HTTP-3，SOCKS5 前端）

用法：
  warp [选项]

代理：
  -l <host:port>   SOCKS5 监听地址（默认 :40000，同时接受 IPv4 与 IPv6 客户端）
  -user <用户名>   SOCKS5 用户名；必须同时给出 -user 和 -pass 才启用认证
  -pass <密码>     SOCKS5 密码
  -ip <取值>       连接哪个边缘（默认 4）：
                     4            注册信息中的 IPv4 边缘
                     6            注册信息中的 IPv6 边缘
                     <host:port>  改为连接指定地址，例如 162.159.198.2:4500、
                                  [2606:4700:103::2]:443、example.com:443
                   它决定的是"如何到达边缘"，不限制隧道内能访问什么 —— 目标
                   由边缘代为连接，所以走 IPv4 边缘一样能访问 IPv6-only 站点。
                   取 4 或 6 时会遍历注册给出的整个端口列表；给显式 host:port
                   时只使用该端口。域名由系统解析器解析（此时隧道尚未建立），
                   解析出的每个地址都会作为候选。

注册：
  -reg             尚未注册时执行注册，然后退出
  -del             向 API 注销并删除本地注册信息

注册信息保存在工作目录下的 reg.json。首次使用需先注册：启动本身从不注册，
因为创建账号是一个需要明确表达的动作。-reg 是幂等的 —— 已有注册时只报告并
退出，而不是替换掉它；替换会让旧注册在 Cloudflare 侧失去本地凭据，再也无法
注销。要更换注册，请先用 -del。

边缘地址与端口列表来自注册信息，因此没有单独的端点参数；端口按 API 返回的
顺序尝试，并从上次成功的那个开始。

示例：
  warp -reg                               注册（首次使用）
  warp                                    用已保存的注册信息运行
  warp -ip 6                              通过 IPv6 连接边缘
  warp -ip 162.159.198.2:4500             指定边缘地址与端口
  warp -ip example.com:443                通过域名连接自定义边缘
  warp -l 127.0.0.1:1080                  只监听回环地址
  warp -l 0.0.0.0:1080 -user u -pass s    对外提供服务并要求认证
  warp -del && warp -reg                  更换注册

注意：
  UDP ASSOCIATE 的数据报不经过 WARP 隧道。plain CONNECT 是字节流隧道，无法
  承载数据报，因此它们从本机网络栈直接发出，对端看到的是你的真实地址。
  TCP 走隧道，UDP 不走。

  默认监听地址接受来自任何位置的连接，且不要求认证。在不可信网络中请绑定
  回环地址（-l 127.0.0.1:40000），或设置 -user 与 -pass。

`)
}

// edgeLookupTimeout bounds the bootstrap name lookup for an -ip hostname.
const edgeLookupTimeout = 10 * time.Second

// resolveEdge turns an explicit -ip value into the candidate address list.
//
// A hostname has to be resolved by the system resolver: this runs before the
// tunnel exists, so the in-tunnel DoH client is not available yet. That means a
// hostname here is visible to the local resolver — the same exposure the
// registration API call already has, but worth knowing about. An IP literal
// avoids it entirely.
//
// Every address the name resolves to becomes a candidate, so a dual-stack
// hostname still works on a single-stack host: the families this host cannot
// route are rejected immediately by the dialer.
func resolveEdge(spec string) ([]string, error) {
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("需要 host:port 形式，例如 162.159.198.2:443、"+
			"[2606:4700:103::2]:443 或 example.com:443（%w）", err)
	}
	if host == "" {
		return nil, errors.New("需要 host:port 形式，主机部分为空")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("端口 %q 不是 1-65535 范围内的数字", port)
	}

	if net.ParseIP(host) != nil {
		return []string{net.JoinHostPort(host, port)}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), edgeLookupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("用系统解析器解析 %q 失败：%w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%q 未解析出任何地址", host)
	}

	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.IP.String(), port))
	}
	return out, nil
}

func main() {
	var (
		listen = flag.String("l", ":40000", "SOCKS5 监听地址 host:port")
		user   = flag.String("user", "", "SOCKS5 用户名（与 -pass 同时给出才启用认证）")
		pass   = flag.String("pass", "", "SOCKS5 密码（与 -user 同时给出才启用认证）")
		ip     = flag.String("ip", "4", "WARP 边缘：4、6，或显式 host:port")
		reg    = flag.Bool("reg", false, "尚未注册时执行注册，然后退出")
		del    = flag.Bool("del", false, "向 API 注销并删除本地注册信息")
	)
	flag.Usage = usage
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// -del and -reg are administrative: each does its one job and exits, so that
	// registering cannot be confused with starting the proxy.
	if *del {
		log.Println("正在注销...")
		if err := registration.DeleteRegistration(defaultStateFile); err != nil {
			log.Fatalf("注销失败：%v", err)
		}
		log.Println("✓ 注销成功")
		return
	}

	if *reg {
		// Registering is idempotent: an existing registration is left alone.
		// Replacing it silently would strand the old one on Cloudflare's side
		// with no local credential left to delete it.
		switch existing, err := registration.Load(defaultStateFile); {
		case err == nil:
			log.Printf("已注册：id=%s（%s）", existing.ID, defaultStateFile)
			log.Println("无需操作。要换一个注册，请先用 -del 注销。")
			return
		case !errors.Is(err, fs.ErrNotExist):
			log.Fatalf("%s 存在但无法读取（%v）。\n"+
				"拒绝覆盖：请删除该文件，或先执行 -del。", defaultStateFile, err)
		}

		regData, err := registration.Register()
		if err != nil {
			log.Fatalf("注册失败：%v", err)
		}
		if err := regData.Save(defaultStateFile); err != nil {
			log.Fatalf("注册信息写入 %s 失败：%v", defaultStateFile, err)
		}
		log.Printf("✓ 注册信息已保存到 %s（id=%s）", defaultStateFile, regData.ID)
		log.Println("不带 -reg 运行即可启动代理。")
		return
	}

	// Starting never registers: creating an account is an explicit act, and
	// doing it implicitly would leave a registration on Cloudflare's side that
	// the user never asked for.
	regData, err := registration.Load(defaultStateFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Fatalf("%s 中没有注册信息。请先执行 warp -reg。", defaultStateFile)
		}
		log.Fatalf("无法读取注册文件 %s：%v", defaultStateFile, err)
	}
	log.Printf("✓ 已注册：id=%s", regData.ID)

	// -ip selects the edge: "4"/"6" pick the family from the registration —
	// which hands out both, though a host reaches only the families its network
	// carries — and anything else is an explicit address that replaces it.
	var edgeAddrs []string
	switch *ip {
	case "4", "6":
		endpointHost, other := regData.EndpointV4, "6"
		if *ip == "6" {
			endpointHost, other = regData.EndpointV6, "4"
		}
		if endpointHost == "" {
			log.Fatalf("注册信息中没有 IPv%s 边缘地址。"+
				"可改用 -ip %s，或依次执行 -del 与 -reg 重新注册。", *ip, other)
		}

		ports := regData.EndpointPorts
		if len(ports) == 0 {
			ports = []int{443}
		}
		for _, p := range ports {
			edgeAddrs = append(edgeAddrs, net.JoinHostPort(endpointHost, strconv.Itoa(p)))
		}
		log.Printf("WARP 代理启动中（边缘=IPv%s %s 端口=%v，socks5=%s）",
			*ip, endpointHost, ports, *listen)

	default:
		var err error
		if edgeAddrs, err = resolveEdge(*ip); err != nil {
			log.Fatalf("-ip %q 既不是 4 或 6，也不是可用地址：%v", *ip, err)
		}
		log.Printf("WARP 代理启动中（边缘=%s → %v，socks5=%s）", *ip, edgeAddrs, *listen)
	}

	// Pin the edge to the endpoint public key from registration, like warp-svc does.
	verifyEdge, err := regData.PeerPublicKeyVerifier()
	if err != nil {
		log.Fatalf("边缘公钥固定初始化失败：%v", err)
	}

	// Build TLS config for MASQUE connection.
	// The SNI is a well-known name rather than the edge's own identity and the
	// chain is signed by a private CA, so the standard chain check cannot apply;
	// authentication comes from pinning the endpoint public key instead.
	tlsConfig := &tls.Config{
		ServerName:            "consumer-masque-proxy.cloudflareclient.com",
		NextProtos:            []string{"h3"},
		InsecureSkipVerify:    true,
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{regData.ClientCert},
		VerifyPeerCertificate: verifyEdge,

		// warp-svc offers only the NIST curves — its ClientCertificateHook sets
		// P-256/P-384/P-521 and never X25519. Go would otherwise lead with
		// X25519, and the edge answers a key share it does not want with a
		// HelloRetryRequest, costing an extra round trip on every handshake.
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
	}
	if verifyEdge != nil {
		log.Println("✓ 边缘公钥固定已启用")
	} else {
		log.Println("⚠ 注册信息中没有边缘公钥，公钥固定已禁用（请重新执行 -reg）")
	}

	// Connect to WARP edge via QUIC/H3
	proxyClient, err := tunnel.NewMasqueClient(edgeAddrs, tlsConfig, regData.Token)
	if err != nil {
		log.Fatalf("MASQUE 连接失败：%v", err)
	}
	defer proxyClient.Close()
	log.Println("✓ MASQUE 连接已建立")

	// Start SOCKS5 proxy server
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("SOCKS5 监听失败：%v", err)
	}
	defer ln.Close()

	socksCfg := tunnel.SOCKS5Config{
		Username: *user,
		Password: *pass,
		AllowUDP: true,
	}

	authInfo := ""
	if *user != "" && *pass != "" {
		authInfo = fmt.Sprintf("（认证用户：%s）", *user)
	}
	log.Printf("SOCKS5 代理监听于 %s%s", *listen, authInfo)
	log.Println("UDP ASSOCIATE 已启用 —— 数据报从本机直接发出，不经过 WARP 隧道")

	// Handle connections
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigCh
		log.Println("正在关闭...")
		cancel()   // signal all HandleSOCKS5 goroutines to stop
		ln.Close() // unblock Accept
	}()

	// Accept errors are not all fatal. Running out of file descriptors or having
	// a client vanish between the SYN and the accept is transient: backing off
	// and continuing keeps the proxy alive, where returning would take the whole
	// process down over a momentary condition.
	const maxAcceptBackoff = time.Second
	var acceptBackoff time.Duration

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // graceful shutdown
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				break // listener gone and not a shutdown we initiated
			}
			if acceptBackoff == 0 {
				acceptBackoff = 5 * time.Millisecond
			} else if acceptBackoff *= 2; acceptBackoff > maxAcceptBackoff {
				acceptBackoff = maxAcceptBackoff
			}
			log.Printf("Accept 出错：%v，%s 后重试", err, acceptBackoff)
			select {
			case <-time.After(acceptBackoff):
			case <-ctx.Done():
				return
			}
			continue
		}
		acceptBackoff = 0
		go proxyClient.HandleSOCKS5(ctx, conn, socksCfg)
	}
}
