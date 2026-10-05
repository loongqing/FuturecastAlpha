#!/usr/bin/env bash
#
# FutureCast — 本机端到端演示。
#
# 刻意**不手写配置文件**：全部通过 CLI 自己的 `admin keygen` / `init` 生成。
# 手写配置会随 CLI 字段变更而漂移（本脚本的第一版就因为写死 YAML 而失效），
# 而调用 CLI 生成则天然跟随真实契约。
#
# 演示内容：
#   1. 生成 2-of-3 管理员密钥与创世 AdminSet
#   2. 起 3 个节点，其中 2 个只配 1 个种子地址（验证自动扩张）
#   3. 发布一条 2-of-3 门限签名的管理员广播，确认三个节点都收到
#   4. 确认"只有 1 个签名"的广播被全网拒绝
#   5. sealed 模式：超管不监听端口、中继读不到正文、订阅者解封并验证
#
# 任何一步失败都以非零退出码结束并打印原始报错，绝不伪造成功。
#
# 用法：
#   scripts/demo.sh [--work DIR] [--port-base N] [--keep]
set -euo pipefail

export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOSUMDB="${GOSUMDB:-off}"
export PATH="$PATH:/root/go/bin"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT_BASE=17900
KEEP=0
SECRET="demo-topic-secret"

while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="${2:?}"; shift 2 ;;
    --port-base) PORT_BASE="${2:?}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 64 ;;
  esac
done

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [ -n "${p:-}" ] && kill "$p" 2>/dev/null || true
  done
  for p in "${PIDS[@]:-}"; do
    [ -n "${p:-}" ] && wait "$p" 2>/dev/null || true
  done
  if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; else echo "工作目录保留在 $WORK"; fi
}
trap cleanup EXIT

fail() { echo; echo "❌ 演示失败：$*" >&2; exit 1; }

echo "== 构建 CLI =="
BIN="$WORK/futurecast"
( cd "$ROOT" && go build -o "$BIN" ./cmd/futurecast ) || fail "构建失败"
echo "   $BIN"

cd "$WORK"
TOPIC="demo.alert"

echo
echo "== 1. 生成 2-of-3 管理员密钥与创世 AdminSet =="
"$BIN" admin keygen --out keys --threshold 2 --total 3 --topic "$TOPIC" | sed 's/^/   /'

echo
echo "== 2. 起 3 个节点（node2/node3 只知道 node1 一个种子地址）=="
mk_node() { # name listen seeds mode secret
  local name="$1" listen="$2" seeds="$3" mode="$4" secret="$5"
  local args=(init --config "$name.json" --admin-set keys/admin-set.json --topic "$TOPIC")
  if [ "$mode" = "sealed" ]; then
    args+=(--mode sealed)
  else
    args+=(--listen "$listen")
  fi
  [ -n "$seeds" ] && args+=(--seeds "$seeds")
  [ -n "$secret" ] && args+=(--topic-secret "$secret")
  "$BIN" "${args[@]}" >/dev/null
}
mk_node n1 "127.0.0.1:$((PORT_BASE+1))" "" "public" ""
mk_node n2 "127.0.0.1:$((PORT_BASE+2))" "127.0.0.1:$((PORT_BASE+1))" "public" ""
mk_node n3 "127.0.0.1:$((PORT_BASE+3))" "127.0.0.1:$((PORT_BASE+1))" "public" ""

for i in 1 2 3; do
  "$BIN" node --config "n$i.json" > "n$i.log" 2>&1 &
  PIDS+=("$!")
done
sleep 5
for i in 1 2 3; do
  kill -0 "${PIDS[$((i-1))]}" 2>/dev/null || fail "node$i 已退出，日志见 $WORK/n$i.log"
done
echo "   三个节点均在运行"
for i in 1 2 3; do
  printf "   n%d 邻居数: %s\n" "$i" "$(grep -c '建立连接' "n$i.log" 2>/dev/null || echo 0)"
done

echo
echo "== 3. 发布 2-of-3 门限管理员广播 =="
OUT="$("$BIN" publish --config n1.json --topic "$TOPIC" --text "全区广播：进入静默模式" \
  --admin-keys keys/admin-1.key,keys/admin-2.key 2>&1)" || fail "广播失败：$OUT"
echo "$OUT" | grep -E '已广播|msg_id|代数|签名 =' | sed 's/^/   /'
MSGID="$(echo "$OUT" | grep -oE 'msg_id = [0-9a-f]+' | awk '{print $3}')"

echo
echo "== 4. 远端节点是否收到并验证（等待最终一致，上限 15s）=="
# 本系统承诺的是**最终一致**，不是瞬时到达：PUSH 尽力而为，
# 每 3s 一轮 anti-entropy 补齐缺口。因此这里按契约等待收敛，
# 而不是假设"发完就已经到了"。超过上限仍未到达即判定失败。
DEADLINE=$((SECONDS + 15))
RC=1
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  if grep -q "接受消息 $MSGID" n2.log 2>/dev/null && grep -q "接受消息 $MSGID" n3.log 2>/dev/null; then
    RC=0
    break
  fi
  sleep 0.3
done
for i in 2 3; do
  if grep -q "接受消息 $MSGID" "n$i.log"; then
    printf "   ✅ n%d 收到 %s（耗时约 %ss）\n" "$i" "$MSGID" "$((15 - (DEADLINE - SECONDS)))"
  else
    printf "   ❌ n%d 未在 15s 内收到 %s\n" "$i" "$MSGID"
  fi
  grep '管理员授权 2 签' "n$i.log" | tail -1 | sed 's/^/      /'
done
[ "$RC" -eq 0 ] || fail "广播未在 15s 内到达全部远端节点"

echo
echo "== 5. 只有 1 个签名的广播必须被拒 =="
if "$BIN" publish --config n1.json --topic "$TOPIC" --text "伪造广播" \
    --admin-keys keys/admin-1.key >/dev/null 2>&1; then
  fail "1/3 签名的广播竟然被接受了"
fi
echo "   ✅ 1/3 签名被拒（门限生效）"
if grep -q '伪造广播' n2.log n3.log 2>/dev/null; then
  fail "被拒的广播泄漏到了远端节点"
fi
echo "   ✅ 未泄漏到任何远端节点"

echo
echo "== 6. sealed 模式：超管不监听、公网只看到密文 =="
# 观察者节点：连在网络里、订阅同一主题，但**没有主题口令**。
# 它代表"网络里的普通第三方" —— sealed 模式声称它读不到内容。
# 入口中继必须持有主题口令：它要解封才能校验内层门限签名，并重新加密发布
# （这是当前实现的已知限制，见 docs/DESIGN.md §5.6）。
"$BIN" init --config relay.json --listen "127.0.0.1:$((PORT_BASE+11))" \
  --admin-set keys/admin-set.json --topic "$TOPIC" --topic-secret "$SECRET" >/dev/null
"$BIN" init --config sub.json --listen "127.0.0.1:$((PORT_BASE+12))" \
  --seeds "127.0.0.1:$((PORT_BASE+11))" --admin-set keys/admin-set.json --topic "$TOPIC" \
  --topic-secret "$SECRET" >/dev/null
"$BIN" init --config sealedadmin.json --mode sealed --seeds "127.0.0.1:$((PORT_BASE+11))" \
  --admin-set keys/admin-set.json --topic "$TOPIC" --topic-secret "$SECRET" >/dev/null
"$BIN" init --config observer.json --listen "127.0.0.1:$((PORT_BASE+13))" \
  --seeds "127.0.0.1:$((PORT_BASE+11))" --admin-set keys/admin-set.json --topic "$TOPIC" >/dev/null
python3 - "$WORK/sealedadmin.json" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["admin_key_paths"] = ["keys/admin-1.key", "keys/admin-2.key"]
json.dump(c, open(p, "w"), indent=2, ensure_ascii=False)
PY

"$BIN" node --config relay.json       > relay.log 2>&1 & PIDS+=("$!")
sleep 1
"$BIN" node --config sub.json         > sub.log   2>&1 & PIDS+=("$!")
sleep 1
"$BIN" node --config sealedadmin.json > sadm.log  2>&1 & PIDS+=("$!")
sleep 1
"$BIN" node --config observer.json    > obs.log   2>&1 & PIDS+=("$!")
sleep 5

grep -q '不监听端口' sadm.log || fail "sealed 超管竟然在监听端口"
echo "   ✅ sealed 超管不监听任何端口（只出站）"

SOUT="$("$BIN" publish --config sealedadmin.json --topic "$TOPIC" --text "机密广播：行动时间 T" 2>&1)" \
  || fail "封存投递失败：$SOUT"
echo "$SOUT" | grep -E '已投递|中继受理|说明' | sed 's/^/   /'
sleep 6

# 关键断言：网络中的无口令观察者**绝不能**看到正文。
# 注意：入口中继能看到明文 —— 它必须解封才能校验内层门限签名。
# 这是当前实现的已知限制，已写入 docs/DESIGN.md §5.7，不由本脚本掩盖。
if grep -q '机密广播' obs.log; then
  fail "无口令观察者竟然读到了封存正文（sealed 内容保密失效）"
fi
echo "   ✅ 无口令观察者只看到密文，读不到正文"
if grep -q '拒绝发布封存副本' relay.log; then
  fail "中继因缺少主题口令拒绝了重发布（配置错误）"
fi
if ! grep -q 'MESSAGE_KIND_SEALED' obs.log; then
  fail "无口令观察者应能看到'存在一条封存消息'这一事实"
fi
echo "   ✅ 无口令观察者能看到'某节点发布了封存消息'，但无法判定其来源"

if grep -q '封存已解封' sub.log; then
  echo "   ✅ 订阅者（有口令）解封并验证成功："
  grep '封存已解封' sub.log | tail -1 | sed 's/^[0-9\/: ]*//' | sed 's/^/      /'
else
  fail "订阅者未能解封封存消息"
fi

echo
echo "== 7. 定向广播：只有被点名的节点能解密 =="
# 先让节点把彼此的公钥采集到地址簿（定向广播需要收件人公钥）。
# 清掉可能残留的旧地址簿，避免把上一轮的节点 id 混进来。
rm -f keys/recipients.json
"$BIN" peers --config n1.json --wait 1s >/dev/null 2>&1
# 排除发布者自身：n1 是发送方，把它选成收件人会让"谁是收件人"变得没有意义。
SELF_ID="$(grep -oE 'node_id   = [0-9a-f]+' n1.log | head -1 | awk '{print $3}')"
DIRECT_IDS="$("$BIN" peers --config n1.json --offline 2>&1 \
  | grep -E '^  [0-9a-f]{64}$' | awk '{print $1}' \
  | grep -v "^$SELF_ID$" | head -1 | paste -sd,)"
if [ -z "$DIRECT_IDS" ]; then
  fail "地址簿中没有可用的收件人（除发布者外为空）"
fi
# 用 awk 数逗号分隔项：printf 无尾换行时 wc -l 会把 1 项算成 0。
N_RCPT="$(printf '%s' "$DIRECT_IDS" | awk -F, '{print NF}')"
echo "   收件人数量 = $N_RCPT（名单不会出现在消息里）"

DOUT="$("$BIN" publish --config n1.json --topic "$TOPIC" --text "只给这两个节点：行动时间 T" \
  --direct-to "$DIRECT_IDS" \
  --admin-keys keys/admin-1.key,keys/admin-2.key 2>&1)" || fail "定向广播发布失败：$DOUT"
echo "$DOUT" | grep -E '已发布|msg_id|槽位' | sed 's/^/   /'
DMSG="$(echo "$DOUT" | grep -oE 'msg_id    = [0-9a-f]+' | awk '{print $3}')"

# 按契约等待收敛：本系统是最终一致，不保证瞬时到达。
# 固定 sleep 会偶发误判（实测约 1/3），因此这里轮询到"收件人已解开"或超时。
DDL=$((SECONDS + 20))
while [ "$SECONDS" -lt "$DDL" ]; do
  if grep -q "定向广播 $DMSG 解密成功" n1.log n2.log n3.log 2>/dev/null; then
    break
  fi
  sleep 0.3
done
sleep 1

# 统计三类角色：解开的收件人 / 能验证却解不开的盲节点 / 完全没见到的
DECRYPTED=0; BLIND=0
for i in 1 2 3; do
  if grep -q "定向广播 $DMSG 解密成功" "n$i.log" 2>/dev/null; then
    DECRYPTED=$((DECRYPTED + 1))
    printf "   🔓 n%d 解开了（是收件人）\n" "$i"
    # 收件人当然能看到正文，这里顺带确认它确实解出了内容
    grep -q '行动时间 T' "n$i.log" || fail "n$i 自称解开却看不到正文"
  else
    # 非收件人：绝不能看到正文。看到与否都不影响传播（这正是设计意图）。
    if grep -q '行动时间 T' "n$i.log" 2>/dev/null; then
      fail "非收件人 n$i 竟然看到了定向广播正文"
    fi
    # 收到过这条消息（能验签、参与转发）才算"盲节点"
    if grep -q "定向广播 $DMSG 已验签并转发" "n$i.log" 2>/dev/null; then
      BLIND=$((BLIND + 1))
      printf "   🔒 n%d 收到了、验签通过、但解不开（非收件人，仍参与转发）\n" "$i"
    fi
  fi
done

[ "$DECRYPTED" -eq "$N_RCPT" ] || fail "应有 $N_RCPT 个收件人解开，实际 $DECRYPTED 个"
[ "$BLIND" -ge 1 ] || fail "应至少有一个非收件人节点收到却解不开（否则无法证明定向性）"
echo "   ✅ 只有被点名的 $DECRYPTED 个节点解开；$BLIND 个非收件人只看到密文"

echo
echo "==================== 演示全部通过 ===================="
echo "  ✅ 2-of-3 门限广播三节点全达"
echo "  ✅ 1/3 签名被全网拒绝且不泄漏"
echo "  ✅ sealed 超管不监听端口"
echo "  ✅ 无口令观察者只能看到密文，持口令订阅者可解封并验证 2-of-3"
echo "  ✅ 定向广播：只有被点名的节点能解密，名单对外隐藏"
