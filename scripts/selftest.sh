#!/usr/bin/env bash
#
# FutureCast — 自检：build + vet + test + race，并检查脚本语法。
#
# 用法：
#   scripts/selftest.sh [--no-race] [--no-vet]
# 环境：
#   SKIP_RACE=1   等价于 --no-race
#   SKIP_VET=1    等价于 --no-vet
#
set -euo pipefail

# ---- 环境（本机 proxy.golang.org 不可达，必须用镜像）----
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=off
export PATH="$PATH:/root/go/bin"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DO_RACE=1
DO_VET=1
[ "${SKIP_RACE:-0}" = "1" ] && DO_RACE=0
[ "${SKIP_VET:-0}" = "1" ] && DO_VET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-race) DO_RACE=0; shift ;;
    --no-vet) DO_VET=0; shift ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "错误：未知参数 $1" >&2; exit 64 ;;
  esac
done

LOGDIR="$(mktemp -d)"
trap 'rm -rf "$LOGDIR" || true' EXIT

echo "== FutureCast selftest =="
echo "工作目录 : $ROOT"
echo "GOPROXY  : $GOPROXY"
echo "GOSUMDB  : $GOSUMDB"
go version 2>&1 | sed 's/^/Go       : /' || echo "Go       : 未找到 go（构建/测试会失败）"
echo "日志目录 : $LOGDIR"
echo

PASS=0
FAIL=0
ENVSKIP=0
declare -a RESULTS=()

# ENV_PATTERN：若设置，且该步骤的失败仅由该模式（例如 TSan 在本沙箱不可用）
# 造成，则记为 ENV（环境限制）而不是 FAIL —— 但绝不用它掩盖真正的代码失败：
# 日志里只要出现 "--- FAIL" 或 "# futurecast" 编译错误，仍然判 FAIL。
run_step() {
  local name="$1"; shift
  local envpat="${ENV_PATTERN:-}"
  local log="$LOGDIR/${name//[^A-Za-z0-9_.-]/_}.log"
  printf '==> %-28s' "$name"
  # 注意：不能写成 `if "$@"; then ...; fi; rc=$?` —— 条件为假且无 else 时
  # if 复合命令的退出码是 0，会丢失真实退出码。这里先取状态再判断。
  local rc=0
  set +e
  "$@" >"$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "PASS"
    RESULTS+=("PASS  $name")
    PASS=$((PASS + 1))
    return 0
  fi
  if [ -n "$envpat" ] && grep -qF -- "$envpat" "$log" \
     && ! grep -qE '^(--- FAIL|# futurecast)' "$log"; then
    echo "ENV (环境限制，不计为失败)"
    RESULTS+=("ENV   $name  (环境限制: $envpat)")
    ENVSKIP=$((ENVSKIP + 1))
    return 0
  fi
  echo "FAIL (exit=$rc)"
  RESULTS+=("FAIL  $name  (exit=$rc, log: $log)")
  FAIL=$((FAIL + 1))
  echo "---- $name 输出（末 40 行）----"
  tail -n 40 "$log" || true
  echo "-------------------------------"
}

run_step "go build ./..."        go build ./...
run_step "go test ./..."         go test ./...
if [ "$DO_VET" = "1" ]; then
  run_step "go vet ./..."        go vet ./...
fi
if [ "$DO_RACE" = "1" ]; then
  # 某些沙箱/内核不允许 TSan 预留所需的 VMA 区间（报 "unsupported VMA range"）。
  # 那属于环境限制，脚本会记为 ENV 而不是代码失败。
  ENV_PATTERN="ThreadSanitizer: unsupported VMA range" \
    run_step "go test -race ./..." go test -race ./...
fi

# 脚本语法自检
if compgen -G "$ROOT/scripts/*.sh" >/dev/null 2>&1; then
  sh_syntax() {
    local bad=0
    for s in "$ROOT"/scripts/*.sh; do
      bash -n "$s" || { echo "bash -n 失败: $s"; bad=1; }
    done
    return "$bad"
  }
  run_step "bash -n scripts/*.sh" sh_syntax
fi

# gofmt 只做提示，不作为失败条件
if command -v gofmt >/dev/null 2>&1; then
  UNFORMATTED="$(gofmt -l . 2>/dev/null | grep -v '^gen/' || true)"
  if [ -n "$UNFORMATTED" ]; then
    echo
    echo "提示：以下文件未被 gofmt 规范化（不判失败）："
    printf '  %s\n' $UNFORMATTED
  fi
fi

echo
echo "==================== 结果 ===================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "----------------------------------------------"
echo "  PASS=$PASS  FAIL=$FAIL  ENV=$ENVSKIP"
echo "=============================================="

if [ "$ENVSKIP" -ne 0 ]; then
  echo "注：有 $ENVSKIP 个步骤因环境限制未判定（见上方 ENV 行）。"
fi
if [ "$FAIL" -ne 0 ]; then
  echo "自检未通过。" >&2
  exit 1
fi
echo "自检通过（代码相关步骤全部通过）。"
