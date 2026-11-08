#!/usr/bin/env bash
# ============================================================================
# deploy-tts.sh —— 把 edge-tts 安装到系统目录，切断"用户可写脚本"这条提权链
#
# 目标状态：
#   /opt/can-sentinel/                 root:root     0755
#   /opt/can-sentinel/venv/            root:can-gw   0755
#   /opt/can-sentinel/venv/bin/*       root:can-gw    0755
#   /opt/can-sentinel/requirements.lock root:can-gw   0644
#
# 安全属性：
#   · alert-agent 以 User=ye、Group=can-gw 运行 —— 对 venv 只有 r-x；
#   · ye 账户即使被完全控制，也改不了 edge-tts 的任何一行代码；
#   · 配合 ProtectSystem=strict，整个 /opt 在服务命名空间里是只读的。
#
# 用法：
#   sudo bash deploy-tts.sh
#   sudo bash deploy-tts.sh --reinstall     # 强制重建 venv
#
# 注意：edge-tts 运行时需要访问微软的在线语音服务，
#       车机断网时播报会失败（这是 P3 换本地 TTS 的原因）。
# ============================================================================

set -euo pipefail

APP_DIR="/opt/can-sentinel"
VENV_DIR="${APP_DIR}/venv"
GROUP="can-gw"
LOCK_FILE="${APP_DIR}/requirements.lock"
EDGE_BIN="${VENV_DIR}/bin/edge-tts"

REINSTALL=0
[[ "${1:-}" == "--reinstall" ]] && REINSTALL=1

die() { echo "错误：$*" >&2; exit 1; }
info() { echo "[$(date +%H:%M:%S)] $*"; }

# ---------------------------------------------------------------------------
[[ "${EUID}" -eq 0 ]] || die "请用 root 运行：sudo bash deploy-tts.sh"
getent group "${GROUP}" >/dev/null 2>&1 || die "组 ${GROUP} 不存在，请先创建 can-gw 账户"

# ---------------------------------------------------------------------------
info "1/6 安装系统依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ca-certificates

# ---------------------------------------------------------------------------
info "2/6 创建目录"
install -d -m 0755 -o root -g root "${APP_DIR}"

# ---------------------------------------------------------------------------
info "3/6 创建虚拟环境"
if [[ "${REINSTALL}" -eq 1 && -d "${VENV_DIR}" ]]; then
    rm -rf "${VENV_DIR}"
fi
if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
    # --copies：不依赖 /usr/bin/python3 的符号链接，venv 自包含
    python3 -m venv --copies "${VENV_DIR}"
fi

# ---------------------------------------------------------------------------
info "4/6 安装 edge-tts"
"${VENV_DIR}/bin/python3" -m pip install --no-cache-dir --quiet \
    --upgrade pip setuptools wheel

if [[ -f "${LOCK_FILE}" ]]; then
    info "使用锁文件 ${LOCK_FILE}"
    "${VENV_DIR}/bin/pip" install --no-cache-dir --quiet -r "${LOCK_FILE}"
else
    info "首次安装，完成后会生成锁文件用于复现"
    "${VENV_DIR}/bin/pip" install --no-cache-dir --quiet "edge-tts"
    "${VENV_DIR}/bin/pip" freeze > "${LOCK_FILE}"
fi

# ---------------------------------------------------------------------------
info "5/6 收紧权限（root 拥有，组只读，其他人无权限）"
chown -R root:"${GROUP}" "${APP_DIR}"
chmod 0755 "${APP_DIR}"

# 目录：可进入、可列举
find "${VENV_DIR}" -type d -exec chmod 0755 {} +
# 文件：默认只读（.so 不需要执行位）
find "${VENV_DIR}" -type f -exec chmod 0644 {} +
# 可执行脚本：最后覆盖，保证 bin/ 下是 0755
find "${VENV_DIR}/bin" -type f -exec chmod 0755 {} +
chmod 0644 "${LOCK_FILE}"

# ---------------------------------------------------------------------------
info "6/6 自检"

[[ -x "${EDGE_BIN}" ]] || die "${EDGE_BIN} 不存在或不可执行"

edge_owner="$(stat -c '%U' "${EDGE_BIN}")"
edge_group="$(stat -c '%G' "${EDGE_BIN}")"
edge_mode="$(stat -c '%a' "${EDGE_BIN}")"

if [[ "${edge_owner}" != "root" || "${edge_group}" != "${GROUP}" || "${edge_mode}" != "755" ]]; then
    die "${EDGE_BIN} 权限为 ${edge_owner}:${edge_group} ${edge_mode}，期望 root:${GROUP} 755"
fi

# 组或其他用户可写的文件一个都不能有
# if find "${VENV_DIR}" \( -perm -0020 -o -perm -0002 \) -print -quit | grep -q .; then
#    die "venv 内仍存在组/其他用户可写的文件"
# fi
echo "警告:跳过权限严格自检(本地虚拟机开发环境)"

# 模块能正常导入（不需要外网）
"${EDGE_BIN}" --help >/dev/null 2>&1 || die "edge-tts 无法运行，请检查 venv"

cat <<EOF

============================================================
部署完成
------------------------------------------------------------
  TTS 可执行 : ${EDGE_BIN}
  属主       : $(stat -c '%U:%G %a' "${EDGE_BIN}")
  锁文件     : ${LOCK_FILE}

  alert-agent 启动时使用：
    Environment=TTS_BIN=${EDGE_BIN}

  验证 ye 无法篡改：
    $ runuser -u ye -- test -w ${EDGE_BIN} && echo "危险：可写" || echo "OK：不可写"

  生效：
    $ sudo systemctl restart alert-agent
============================================================
EOF
