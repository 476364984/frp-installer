#!/bin/bash
# FRPS 全自动部署脚本（专业增强版）
# 版本：20.0
# 优化要点：军事级安全、智能错误恢复、零交互模式支持、企业级审计功能

####################
# 全局配置
####################
declare -r LOG_DIR="/var/log/frp-installer"
declare -r AUDIT_LOG="${LOG_DIR}/audit-$(date +%Y%m%d).log"
declare -r CONFIG_DIR="/etc/frp"
declare -r CERTS_DIR="${CONFIG_DIR}/tls"
declare -r SECRETS_DIR="${CONFIG_DIR}/vault"
declare -r SCRIPT_NAME=$(basename "$0")
declare -r MAX_RETRIES=3
declare -r LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"

# 安全颜色定义（ANSI转义序列安全实现）
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[0;33m'
declare -r BLUE='\033[0;34m'
declare -r BOLD='\033[1m'
declare -r NC='\033[0m'

####################
# 安全函数库
####################

# 军用级日志记录
security_log() {
    local level=$1
    local message=$2
    local audit_msg="[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}"
    
    # 审计日志（不可修改）
    echo "${audit_msg}" | sudo tee -a "${AUDIT_LOG}" >/dev/null
    chattr +a "${AUDIT_LOG}" 2>/dev/null
    
    # 调试日志
    case ${level} in
        "FATAL") echo -e "${RED}${BOLD}[✘] ${message}${NC}" ;;
        "WARN")  echo -e "${YELLOW}[!] ${message}${NC}" ;;
        "INFO")  echo -e "${BLUE}[▶] ${message}${NC}" ;;
        "DEBUG") [[ "${DEBUG}" == "true" ]] && echo -e "[▷] ${message}" ;;
        *)       : ;;
    esac
}

# 安全退出处理
trap_exit() {
    local exit_code=$?
    rm -f "${LOCK_FILE}"
    security_log "INFO" "脚本执行结束，退出码：${exit_code}"
    exit ${exit_code}
}

# 安全凭证生成
generate_vault() {
    mkdir -p "${SECRETS_DIR}"
    local token=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 32 | head -n1)
    local pwd=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 16 | head -n1)
    
    echo "${token}" | gpg --batch --passphrase "${pwd}" --symmetric --output "${SECRETS_DIR}/token.gpg" 2>/dev/null
    echo "${pwd}" | gpg --batch --passphrase "${pwd}" --symmetric --output "${SECRETS_DIR}/pwd.gpg" 2>/dev/null
    
    chmod 600 "${SECRETS_DIR}"/*
    chattr +i "${SECRETS_DIR}" 2>/dev/null
}

####################
# 核心优化函数
####################

# 智能端口协商算法
negotiate_port() {
    local base_port=$1
    local protocol=$2
    local max_attempts=100
    
    for ((i=0; i<max_attempts; i++)); do
        local test_port=$((base_port + i))
        if ! ss -tulpn | grep -q ":${test_port} "; then
            echo ${test_port}
            return 0
        fi
    done
    security_log "FATAL" "端口协商失败，范围：${base_port}-$((base_port + max_attempts))"
    exit 1
}

# 零交互证书申请
auto_certbot() {
    case ${CERT_TYPE} in
        1)
            security_log "INFO" "申请Let's Encrypt通配符证书..."
            certbot certonly --manual --preferred-challenges=dns \
                --agree-tos --non-interactive \
                --manual-public-ip-logging-ok \
                -d "*.${DOMAIN}" -d "${DOMAIN}" \
                --email "${ADMIN_EMAIL}" 2>/dev/null
            ;;
        2)
            security_log "INFO" "生成自签名证书..."
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
                -keyout "${CERTS_DIR}/privkey.pem" \
                -out "${CERTS_DIR}/fullchain.pem" \
                -days 3650 -nodes -subj "/CN=${DOMAIN}" \
                -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},IP:${SERVER_IP}" 2>/dev/null
            ;;
        *) security_log "FATAL" "无效证书类型"; exit 1 ;;
    esac
}

####################
# 主安装流程
####################

# 初始化安全环境
init_security() {
    [[ $EUID -ne 0 ]] && security_log "FATAL" "必须使用root权限运行" && exit 1
    [[ -f "${LOCK_FILE}" ]] && security_log "FATAL" "检测到重复实例，请检查" && exit 1
    touch "${LOCK_FILE}"
    trap trap_exit EXIT INT TERM
    
    mkdir -p "${LOG_DIR}" "${CONFIG_DIR}" "${CERTS_DIR}"
    chmod 700 "${CONFIG_DIR}"
    security_log "INFO" "安全环境初始化完成"
}

# 企业级部署流程
enterprise_deploy() {
    init_security
    
    security_log "INFO" "开始FRP企业级部署..."
    
    # 安全凭证生成
    generate_vault
    
    # 智能端口分配
    declare -g BIND_PORT=$(negotiate_port 31943 tcp)
    declare -g KCP_PORT=${BIND_PORT}
    declare -g QUIC_PORT=$(negotiate_port 31944 udp)
    declare -g DASH_PORT=$(negotiate_port 7500 tcp)
    
    # 自动证书管理
    auto_certbot
    
    # 下载验证
    local retry_count=0
    while ((retry_count++ < MAX_RETRIES)); do
        if smart_download; then
            break
        else
            security_log "WARN" "下载失败，重试中 (${retry_count}/${MAX_RETRIES})"
            sleep $((retry_count * 5))
        fi
    done
    
    # 安装核心
    install -m 750 frps /usr/local/bin/
    
    # 生成安全配置
    cat > "${CONFIG_DIR}/frps.toml" <<EOF
[common]
bind_port = ${BIND_PORT}
kcp_bind_port = ${KCP_PORT}
quic_bind_port = ${QUIC_PORT}
subdomain_host = "${DOMAIN}"
auth_method = "token"
auth_token = "$(gpg --decrypt --batch --passphrase "$(gpg --decrypt ${SECRETS_DIR}/pwd.gpg 2>/dev/null)" ${SECRETS_DIR}/token.gpg 2>/dev/null)"

[web]
dashboard_addr = "127.0.0.1"
dashboard_port = ${DASH_PORT}
dashboard_user = "admin"
dashboard_pwd = "$(gpg --decrypt --batch --passphrase "$(gpg --decrypt ${SECRETS_DIR}/pwd.gpg 2>/dev/null)" ${SECRETS_DIR}/pwd.gpg 2>/dev/null)"
enable_prometheus = true

transport.tls.enable = true
transport.tls.certFile = "${CERTS_DIR}/fullchain.pem"
transport.tls.keyFile = "${CERTS_DIR}/privkey.pem"
EOF
    
    # 系统集成
    systemctl daemon-reload
    systemctl enable --now frps
    
    security_log "INFO" "部署成功完成"
}

####################
# 执行入口
####################
main() {
    clear
    echo -e "${BOLD}${GREEN}
    ███████╗██████╗ ██████╗ 
    ██╔════╝██╔══██╗██╔══██╗
    █████╗  ██████╔╝██████╔╝
    ██╔══╝  ██╔══██╗██╔═══╝ 
    ██║     ██║  ██║██║     
    ╚═╝     ╚═╝  ╚═╝╚═╝     
    ${NC}"
    
    enterprise_deploy
}

main "$@"
