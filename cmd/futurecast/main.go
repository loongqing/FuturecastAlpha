// Command futurecast 是 FutureCast 去中心化广播系统的节点与工具入口。
package main

import (
	"os"

	"github.com/loongqing/FuturecastAlpha/internal/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:])) }
