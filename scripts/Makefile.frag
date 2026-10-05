# FutureCast — 建议加入根 Makefile 的目标片段。
#
# 不要直接改根 Makefile（那属于 Lead 的写域）。合并方式二选一：
#   include scripts/Makefile.frag
#   cat scripts/Makefile.frag >> Makefile
#
# 本机 proxy.golang.org 不可达，所有 Go 目标都必须带镜像环境变量。

GO          ?= go
GOPROXY     ?= https://goproxy.cn,direct
GOSUMDB     ?= off
GOENV       := GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) PATH=$$PATH:/root/go/bin
PROTOC      ?= protoc
PROTO_SRC   := proto/futurecast/v1
BIN         := bin/futurecast

.PHONY: help env proto build test race vet selftest keygen demo clean

help: ## 显示可用目标
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

env: ## 打印本机必需的环境变量
	@echo 'export GOPROXY=$(GOPROXY)'
	@echo 'export GOSUMDB=$(GOSUMDB)'
	@echo 'export PATH=$$PATH:/root/go/bin'

proto: ## 由 .proto 重新生成 Go 绑定
	$(PROTOC) --proto_path=proto \
		--go_out=. --go_opt=module=github.com/loongqing/FuturecastAlpha \
		$(PROTO_SRC)/*.proto

build: ## go build ./...
	$(GOENV) $(GO) build ./...

test: ## go test ./...
	$(GOENV) $(GO) test ./...

race: ## go test -race ./...
	$(GOENV) $(GO) test -race ./...

vet: ## go vet ./...
	$(GOENV) $(GO) vet ./...

selftest: ## 运行 scripts/selftest.sh（build+vet+test+race）
	bash scripts/selftest.sh

keygen: ## 生成 2-of-3 管理员密钥环（需 CLI）
	bash scripts/keygen.sh --out ./admin-keys --threshold 2 --total 3

demo: ## 三节点本机演示（需 CLI）
	bash scripts/demo.sh

clean: ## 清理构建产物
	rm -rf bin coverage.out
