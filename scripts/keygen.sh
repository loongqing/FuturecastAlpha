#!/usr/bin/env bash
#
# FutureCast — 生成 2-of-3 超级管理员密钥环 + 创世 AdminSet。
#
# 依赖：futurecast CLI（cmd/futurecast，已实现）。
#       CLI 不存在时本脚本明确报错退出（exit 2），绝不伪造成功输出。
#
# 用法：
#   scripts/keygen.sh [--out DIR] [--threshold 2] [--total 3] [--bin PATH]
# 环境：
#   FUTURECAST_BIN   指定 CLI 可执行文件路径（优先级最高）
#   FC_KEYGEN_OUT    等价于 --out
#
set -euo pipefail

# ---- 环境（本机 proxy.golang.org 不可达，必须用镜像）----
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=off
export PATH="$PATH:/root/go/bin"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${FC_KEYGEN_OUT:-$ROOT/admin-keys}"
THRESHOLD=2
TOTAL=3
BIN_ARG="${FUTURECAST_BIN:-}"

usage() {
  sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?--out 需要目录参数}"; shift 2 ;;
    --threshold) THRESHOLD="${2:?--threshold 需要数字}"; shift 2 ;;
    --total) TOTAL="${2:?--total 需要数字}"; shift 2 ;;
    --bin) BIN_ARG="${2:?--bin 需要路径}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "错误：未知参数 $1（用 --help 查看用法）" >&2; exit 64 ;;
  esac
done

case "$THRESHOLD$TOTAL" in
  *[!0-9]*) echo "错误：--threshold/--total 必须是正整数" >&2; exit 64 ;;
esac
if [ "$THRESHOLD" -lt 1 ] || [ "$THRESHOLD" -gt "$TOTAL" ]; then
  echo "错误：门限必须落在 [1, total]，当前 threshold=$THRESHOLD total=$TOTAL" >&2
  exit 64
fi

TMPDIR_FC=""
cleanup() {
  # 注意：EXIT trap 内若有命令返回非零，set -e 会覆盖真正的退出码。
  # 因此这里显式容错并以 return 0 结束。
  if [ -n "$TMPDIR_FC" ]; then rm -rf "$TMPDIR_FC" || true; fi
  return 0
}
trap cleanup EXIT

# ---- 1. 定位 CLI ----
resolve_bin() {
  if [ -n "$BIN_ARG" ]; then printf '%s\n' "$BIN_ARG"; return 0; fi
  if [ -x "$ROOT/bin/futurecast" ]; then printf '%s\n' "$ROOT/bin/futurecast"; return 0; fi
  if command -v futurecast >/dev/null 2>&1; then command -v futurecast; return 0; fi
  if compgen -G "$ROOT/cmd/futurecast/*.go" >/dev/null 2>&1; then
    TMPDIR_FC="$(mktemp -d)"
    echo "构建 futurecast CLI → $TMPDIR_FC/futurecast" >&2
    if ( cd "$ROOT" && go build -o "$TMPDIR_FC/futurecast" ./cmd/futurecast ); then
      printf '%s\n' "$TMPDIR_FC/futurecast"; return 0
    fi
    echo "错误：go build ./cmd/futurecast 失败（上方为原始报错）" >&2
    return 1
  fi
  return 1
}

if ! BIN="$(resolve_bin)"; then
  cat >&2 <<'ERR'
错误：找不到 futurecast CLI，无法生成密钥环。

依赖说明：
  * 本脚本依赖 `futurecast admin keygen --out <dir> --threshold N --total M`
    （见 docs/CONTRACTS.md 与 Lead 约定的 CLI 形态）。
  * CLI 已实现：在仓库根目录执行 `make build` 即可得到 ./bin/futurecast。

可选处理：
  1) 在仓库根目录执行 `make build` 后重跑本脚本；
  2) 若你已在别处构建：FUTURECAST_BIN=/path/to/futurecast scripts/keygen.sh ...
  3) 或把二进制放到 ./bin/futurecast。

本脚本不会用其他方式"凑出"密钥环，也不会输出伪造的成功信息。
ERR
  exit 2
fi

echo "== FutureCast 管理员密钥环 =="
echo "CLI        : $BIN"
echo "输出目录   : $OUT"
echo "门限       : $THRESHOLD-of-$TOTAL"
echo

mkdir -p "$OUT"
chmod 700 "$OUT"

# ---- 2. 调用 CLI ----
"$BIN" admin keygen --out "$OUT" --threshold "$THRESHOLD" --total "$TOTAL"

# ---- 3. 校验产物（不通过就报错，不假装成功）----
JSON_FILES=()
KEY_FILES=()
while IFS= read -r f; do
  case "$f" in
    *.json) JSON_FILES+=("$f") ;;
    *) KEY_FILES+=("$f") ;;
  esac
done < <(find "$OUT" -maxdepth 1 -type f | sort)

echo
echo "-- 产物清单 --"
find "$OUT" -maxdepth 1 -type f -printf '  %M %10s  %p\n' | sort -k4 || ls -la "$OUT"

FAIL=0
if [ "${#KEY_FILES[@]}" -lt "$TOTAL" ]; then
  echo "错误：期望至少 $TOTAL 份私钥文件，实际找到 ${#KEY_FILES[@]} 份。" >&2
  FAIL=1
fi
if [ "${#JSON_FILES[@]}" -lt 1 ]; then
  echo "错误：没有找到创世 AdminSet JSON。" >&2
  FAIL=1
fi
if [ "$FAIL" -ne 0 ]; then
  cat >&2 <<'ERR'

CLI 退出码为 0，但产物与约定不符（3 份 keyfile + 1 份 AdminSet JSON）。
请核对 CLI 的实际输出命名与 --out 语义后再重跑。
本脚本不会把这次运行当作成功。
ERR
  exit 1
fi

# ---- 4. 私钥权限收紧到 0600 ----
for f in "${KEY_FILES[@]}"; do chmod 600 "$f"; done
for f in "${JSON_FILES[@]}"; do chmod 644 "$f"; done
echo
echo "已把 ${#KEY_FILES[@]} 份私钥文件权限设为 0600，AdminSet JSON 设为 644。"

# ---- 5. 指纹（供人工核对备份）----
echo
echo "-- 指纹核对（请离线抄写并与备份比对）--"
for f in "${JSON_FILES[@]}"; do
  if command -v sha256sum >/dev/null 2>&1; then
    printf '  AdminSet JSON sha256: %s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f"
  fi
done

if command -v python3 >/dev/null 2>&1 && [ "${#JSON_FILES[@]}" -ge 1 ]; then
  python3 - "${JSON_FILES[@]}" <<'PY'
import base64, json, sys

def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("keyId", "key_id") and isinstance(v, dict) and "value" in v:
                yield v["value"]
            elif k in ("keyId", "key_id") and isinstance(v, str):
                yield v
            else:
                yield from walk(v)
    elif isinstance(node, list):
        for it in node:
            yield from walk(it)

for path in sys.argv[1:]:
    try:
        doc = json.load(open(path))
    except Exception as exc:            # noqa: BLE001
        print(f"  (跳过 {path}：JSON 解析失败 {exc})")
        continue
    ids = list(walk(doc))
    print(f"  {path}: 发现 {len(ids)} 个 key_id")
    for i, raw in enumerate(ids, 1):
        try:
            b = base64.b64decode(raw, validate=True)
            shown = b.hex()
        except Exception:               # noqa: BLE001
            shown = str(raw)
        print(f"    key#{i} = {shown}")
    if not ids:
        print("    （未在 JSON 中识别到 key_id；请以 CLI 自身打印的指纹为准）")
PY
else
  echo "  （未找到 python3：请以 CLI 自身打印的公钥指纹为准）"
fi

echo
echo "完成。重要提醒："
echo "  1) 3 份私钥请分放 3 台离线机/硬件密钥，任一份单独泄露都签不出广播；"
echo "  2) 不要提交进版本库，不要联网传输；"
echo "  3) 请核对上面的指纹后再继续。"
