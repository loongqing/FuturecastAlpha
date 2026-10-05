# FutureCast — 构建与验收
#
# 本机 proxy.golang.org 不可达，必须用 goproxy.cn 镜像；GOSUMDB 也需关闭
# （sum.golang.google.cn 同样不可达）。这三个变量在 CI 与本地都必须一致。

export GOPROXY  ?= https://goproxy.cn,direct
export GOSUMDB  ?= off
export PATH     := $(PATH):/root/go/bin

GO      ?= go
BIN     ?= bin/futurecast
PKGS    := ./...

.PHONY: help env proto build test vet selftest demo keygen race clean

help: ## 显示可用目标
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

env: ## 打印构建环境（排查依赖问题）
	@echo "GOPROXY = $(GOPROXY)"
	@echo "GOSUMDB = $(GOSUMDB)"
	@echo "Go      = $$($(GO) version)"
	@echo "PATH    = $(PATH)"

proto: ## 由 .proto 重新生成 Go 绑定（改协议后必须执行）
	protoc -I proto --go_out=. --go_opt=module=github.com/loongqing/FuturecastAlpha proto/futurecast/v1/*.proto
	@echo "已重新生成 gen/futurecastv1/"

build: ## 编译 CLI
	$(GO) build -o $(BIN) ./cmd/futurecast
	@echo "已生成 $(BIN)"

test: ## 运行全部测试
	$(GO) test $(PKGS) -count=1

vet: ## 静态检查
	$(GO) vet $(PKGS)

race: ## 竞态检测（本机内核 39 位 VA，ThreadSanitizer 不可用 —— 见 docs/CONTRACTS.md §8.7）
	$(GO) test -race $(PKGS)

selftest: ## build + vet + test + bash -n 一次跑完
	@bash scripts/selftest.sh

demo: ## 本机端到端演示（三节点广播 + sealed 模式）
	@bash scripts/demo.sh

keygen: ## 生成 2-of-3 管理员密钥环
	@bash scripts/keygen.sh

clean: ## 清理构建产物
	rm -rf bin
	$(GO) clean -cache -testcache 2>/dev/null || true
