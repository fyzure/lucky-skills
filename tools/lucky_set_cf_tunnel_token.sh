#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="/etc/lucky-skills"
CONFIG_FILE="${CONFIG_DIR}/cloudflare-tunnel.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo lucky-set-cf-tunnel-token" >&2
  exit 1
fi

install -d -m 0700 -o root -g root "${CONFIG_DIR}"

printf '请输入 Cloudflare Tunnel token（输入不会回显）： '
IFS= read -r -s token
printf '\n'

token="${token//$'\r'/}"
token="${token//$'\n'/}"

if [[ -z "${token}" ]]; then
  echo "Token 不能为空。" >&2
  exit 1
fi

# Cloudflare tunnel token 通常是较长的 URL-safe/JWT-like 字符串。
# 这里只做最小安全检查，不把格式写死，避免 Cloudflare 后续格式变化。
if [[ ${#token} -lt 40 ]]; then
  echo "Token 看起来过短，已拒绝写入。" >&2
  exit 1
fi

tmp="$(mktemp "${CONFIG_DIR}/.cloudflare-tunnel.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
chmod 0600 "${tmp}"
chown root:root "${tmp}"

# 使用 shell-safe 单引号转义；不会输出 token。
escaped=${token//\'/\'\\\'\'}
printf "CLOUDFLARE_TUNNEL_TOKEN='%s'\n" "${escaped}" > "${tmp}"

mv -f "${tmp}" "${CONFIG_FILE}"
chmod 0600 "${CONFIG_FILE}"
chown root:root "${CONFIG_FILE}"
trap - EXIT

unset token escaped

echo "已保存到 ${CONFIG_FILE}"
echo "权限：root:root 0600"
echo "Token 内容未输出。"

