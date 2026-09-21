# tcpbrutal-controller

这是一个 Go 编写的 TCP Brutal v2 控制程序，负责安装 TCP Brutal、根据已建立的 TCP 连接自动发现目标 IP，并管理 TCP Brutal 规则。

TCP Brutal v2 的规则按“目标 IP/CIDR”匹配，不按端口匹配。控制程序因此扫描 `/proc/net/tcp` 和 `/proc/net/tcp6`，根据用户设置的本地端口、远端端口或两者，发现连接的远端 IP，并为每个 IP 创建 `/32` 或 `/128` 规则。规则会覆盖这个 IP 的全部 TCP 端口。

## 构建

```bash
go build -trimpath -o tcpbrutal .
sudo install -m 0755 tcpbrutal /usr/local/bin/tcpbrutal
```

运行环境要求：Linux 5.10 或更新版本、Go 1.19 或更新版本、`iproute2`。安装命令会调用 TCP Brutal 官方安装脚本，该脚本需要 DKMS、当前内核 headers、编译器和网络访问。

## 安装 TCP Brutal

```bash
sudo tcpbrutal install
# 也可以指定版本
sudo tcpbrutal install --version v2.0.0
```

安装命令下载并执行 `https://tcp.hy2.sh/` 的官方脚本，完成 DKMS 模块安装和 `brutalctl` 安装，然后检查 `/proc/net/tcp_brutal/rules` 是否可用。

## 按端口自动发现 IP

服务端监听端口通常使用本地端口匹配：

```bash
sudo tcpbrutal watch add \
  --ports 443,8000-8100 \
  --match local \
  --rate 100
```

客户端连接远端服务端口时使用远端端口匹配：

```bash
sudo tcpbrutal watch add --ports 443 --match remote --rate 50 --gain 20
```

可选的 `--match` 值是 `local`、`remote` 和 `either`。一个策略的速率是每个目标 IP 的共享速率；同一目标 IP 的多个连接共同使用它。

策略写入状态文件后，由 `run` 或 systemd 服务执行扫描和同步。要立即同步一次，可以运行 `sudo tcpbrutal run --once`。

查看和删除端口策略：

```bash
sudo tcpbrutal watch list
sudo tcpbrutal watch delete 1
```

删除策略会删除它发现的规则。手动删除某个规则后，控制程序会将该 IP 加入排除列表，防止后台扫描立即重新添加：

```bash
sudo tcpbrutal rules delete 203.0.113.5
sudo tcpbrutal exclude list
sudo tcpbrutal exclude delete 203.0.113.5
```

## 手动规则和查看

```bash
sudo tcpbrutal rules add --rate 100 203.0.113.5
sudo tcpbrutal rules list
sudo tcpbrutal rules list --json
```

`--rate` 使用 Mbps，范围是 0.5 到 1,000,000。`--gain` 范围是 5 到 80，推荐值是 20。默认会创建带 `congctl lock brutal` 的路由；如果路由由其他程序管理，可以使用 `--no-route`。需要允许应用自行设置 TCP 参数时使用 `--no-lock`。

`rules list` 同时显示持久化规则、内核实时规则、匹配连接数、发送字节数和由本程序创建的路由。内核中存在但不在状态文件里的规则会标记为 `external`，不会被本程序删除或修改。

## 后台运行

先确认模块已经安装和加载，再安装 systemd 服务：

```bash
sudo tcpbrutal service install --interval 2s
sudo tcpbrutal service status
```

服务会周期性扫描已建立连接，默认每 2 秒同步一次。也可以手动运行一次：

```bash
sudo tcpbrutal run --once
```

## 注意事项

- 规则只对新建立的连接生效；已有连接不会因为新增规则而切换。
- 规则按目标 IP 生效，不能只限制某一个目标端口。
- 自动发现依赖 `/proc/net/tcp*`，只能看到本机网络命名空间中的连接。
- 规则状态保存在 `/etc/tcpbrutal/state.json`，文件权限为 `0600`；规则本身仍由内核模块保存，重启后需要 systemd 服务或 `run` 重新恢复。
- 本程序不会覆盖非 TCP Brutal 路由。如果目标前缀已有其他路由，需使用 `--no-route` 并自行配置 `congctl brutal` 路由。

## 开发检查

```bash
gofmt -w main.go internal/controller/*.go
go test ./...
go vet ./...
```
