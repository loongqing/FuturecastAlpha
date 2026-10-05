package cli

import (
	"errors"
	"fmt"
	"os"
)

// Run 是 CLI 入口，返回进程退出码。
func Run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 64
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(os.Stdout)
		return 0
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit(args[1:])
	case "node":
		err = cmdNode(args[1:])
	case "status":
		err = cmdStatus(args[1:])
	case "peers":
		err = cmdPeers(args[1:])
	case "publish":
		err = cmdPublish(args[1:])
	case "verify":
		err = cmdVerify(args[1:])
	case "admin":
		err = runAdmin(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "futurecast: 未知子命令 %q\n\n", args[0])
		printUsage(os.Stderr)
		return 64
	}
	return reportErr(err)
}

func runAdmin(args []string) error {
	if len(args) == 0 {
		return usageErrorf("admin 需要子命令：keygen | set | rotate | compose | sign | finalize")
	}
	switch args[0] {
	case "keygen":
		return cmdAdminKeygen(args[1:])
	case "set":
		return cmdAdminSet(args[1:])
	case "rotate":
		return cmdAdminRotate(args[1:])
	case "compose":
		return cmdAdminCompose(args[1:])
	case "sign":
		return cmdAdminSign(args[1:])
	case "finalize":
		return cmdAdminFinalize(args[1:])
	default:
		return usageErrorf("未知的 admin 子命令 %q", args[0])
	}
}

// reportErr 把错误映射为退出码。
func reportErr(err error) int {
	if err == nil {
		return 0
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(os.Stderr, "用法错误：%s\n", ue.Error())
		return 64
	}
	fmt.Fprintf(os.Stderr, "错误：%v\n", err)
	return 1
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `FutureCast —— 去中心化网络广播系统

用法：
  futurecast <子命令> [选项]

节点：
  init       生成一份节点配置
  node       启动节点（阻塞运行）
  status     打印一次节点状态快照后退出
  peers      列出已知节点的完整 node_id（供定向广播选用）
  publish    发布广播（普通 / 定向 / 封存）

管理员（离线操作）：
  admin keygen    生成 M-of-N 管理员密钥环与创世 AdminSet
  admin set       由密钥环构建指定代数的 AdminSet
  admin rotate    用旧集合门限密钥为新集合收集轮换签名
  admin compose   组装一条待签名的管理员广播正文
  admin sign      用一把密钥签一个 SignedBody
  admin finalize  收集门限签名并写出完整信封（自带校验）

校验：
  verify     离线校验一个信封

示例：
  # 1) 生成 2-of-3 管理员密钥与创世集合
  futurecast admin keygen --out admin-keys --threshold 2 --total 3

  # 2) 建网：第一台做种子
  futurecast init --config seed.json --listen 0.0.0.0:7777 --admin-set admin-keys/admin-set.json
  futurecast node --config seed.json

  # 3) 加入：只知道一个种子地址即可自动扩张
  futurecast init --config node2.json --seeds 10.0.0.1:7777 --admin-set admin-keys/admin-set.json
  futurecast node --config node2.json

  # 4a) 定向广播：只有被点名的节点能解密
  futurecast peers --config seed.json            # 先查已知 node_id
  futurecast publish --config seed.json --topic alerts --text "只给你们三个" \
      --direct-to <node_id_1>,<node_id_2> \
      --admin-keys admin-keys/admin-1.key,admin-keys/admin-2.key

  # 4b) 广播（public 模式：门限签名明文，任何节点可验证）
  futurecast publish --config seed.json --topic alerts --text "进入静默模式" \
      --admin-keys admin-keys/admin-1.key,admin-keys/admin-2.key

  # 5) sealed 模式：不监听、只出站，门限签名与内容都封存
  futurecast init --config admin.json --mode sealed --seeds 10.0.0.1:7777 \
      --admin-set admin-keys/admin-set.json --topic-secret '你的口令'
  futurecast publish --config admin.json --topic alerts --text "机密广播"

环境变量：
  GOPROXY=https://goproxy.cn,direct   # 本机 proxy.golang.org 不可达，构建时必须用镜像
  GOSUMDB=off
`)
}
