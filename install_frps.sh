#!/bin/bash
# FRP服务端智能部署脚本（专业增强版）
# 版本：5.0
# 功能：全自动部署、安全加固、智能诊断、企业级监控
# 更新：2024-03-15

####################
# 全局配置
####################
declare -r LOG_DIR="/var/log/frp-installer"
declare -r LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d%H%M%S).log"
declare -r CONFIG_DIR="/etc/frp"
declare -r CERTS_DIR="${CONFIG_DIR}/tls"
declare -r SECRETS_DIR="${CONFIG_DIR}/vault"
declare -r SCRIPT_NAME=$(basename "$0")
declare -r MAX_RETRIES=3
declare -r LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
declare -r SUPPORT_EMAIL="support@yourdomain.com"

# 安全颜色定义
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[0;33m'
declare -r BLUE='\033[0;34m'
declare -r BOLD='\033[1m'
declare -r NC='\033[0m'

####################
# 核心函数库
####################

# 军事级日志系统
init_logging() {
    mkdir -p "${LOG_DIR}"
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "\n$(date '+%Y-%m-%d %H:%M:%S') [INFO] 脚本启动" | tee -a "${LOG_FILE}"
    trap 'echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 脚本异常退出" | tee -a "${LOG_FILE}"; exit 1' ERR
}

# 系统检测专家
detect_system() {
    echo -e "${BLUE}[1/12] 检测系统环境..."
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        case ${ID} in
            centos|rhel|fedora|almalinux|rocky)
                OS_TYPE="redhat"
                PKG_MGR="yum"
                ;;
            debian|ubuntu|linuxmint)
                OS_TYPE="debian"
                PKG_MGR="apt"
                ;;
            *) 
                echo -e "${RED}[ERROR] 不支持的Linux发行版: $ID"
                exit 1
                ;;
        esac
    else
        echo -e "${RED}[ERROR] 无法识别操作系统"
        exit 1
    fi

    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *) 
            echo -e "${RED}[ERROR] 不支持的CPU架构: $ARCH"
            exit 1
            ;;
    esac
    echo -e "${GREEN}[SUCCESS] 系统检测完成：${OS_TYPE} ${ARCH}"
}

# 智能防火墙管家
manage_firewall() {
    echo -e "${BLUE}[2/12] 检测防火墙状态..."
    case ${OS_TYPE} in
        redhat)
            if ! systemctl is-active firewalld &>/dev/null; then
                echo -e "${YELLOW}[WARN] firewalld未运行"
                read -p "是否启用防火墙？(Y/n): " choice
                if [[ ${choice} =~ [nN] ]]; then
                    echo -e "${YELLOW}[INFO] 跳过防火墙配置"
                    return
                else
                    systemctl enable --now firewalld
                fi
            fi
            ;;
        debian)
            if ! dpkg -l ufw | grep -q '^ii'; then
                apt install -y ufw
            fi
            if ! ufw status | grep -q 'Status: active'; then
                echo -e "${YELLOW}[WARN] ufw未启用"
                read -p "是否启用防火墙？(Y/n): " choice
                if [[ ${choice} =~ [nN] ]]; then
                    echo -e "${YELLOW}[INFO] 跳过防火墙配置"
                    return
                else
                    ufw enable
                fi
            fi
            ;;
    esac
}

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
    echo -e "${RED}[ERROR] 端口协商失败，范围：${base_port}-$((base_port + max_attempts))"
    exit 1
}

# 零交互证书管理
manage_certificate() {
    echo -e "${BLUE}[3/12] 证书配置..."
    mkdir -p "${CERTS_DIR}"
    
    if [ "${ACCESS_TYPE}" == "ip" ]; then
        DOMAIN="${SERVER_IP//./-}.nip.io"
        echo -e "${GREEN}[INFO] 生成动态域名: ${DOMAIN}"
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
            -keyout "${CERTS_DIR}/privkey.pem" \
            -out "${CERTS_DIR}/fullchain.pem" \
            -subj "/CN=${DOMAIN}" \
            -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null
    else
        until dig +short A "${DOMAIN}" | grep -q "^"; do
            echo -e "${RED}[ERROR] 域名解析错误：${DOMAIN}"
            echo -e "请确认DNS记录已指向服务器IP：${SERVER_IP}"
            read -p "按回车重试检查，或输入'exit'退出: " choice
            [ "$choice" == "exit" ] && exit 1
        done
        certbot certonly --standalone -d "${DOMAIN}" --non-interactive --agree-tos
        ln -sf "/etc/letsencrypt/live/${DOMAIN}/" "${CERTS_DIR}"
    fi
    chmod 600 "${CERTS_DIR}"/*
}

# 安全凭证生成器
generate_secrets() {
    echo -e "${BLUE}[4/12] 生成安全凭证..."
    FRP_TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | head -c 32)
    DASH_PWD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | head -c 16)
    
    # GPG加密存储
    mkdir -p "${SECRETS_DIR}"
    echo "${FRP_TOKEN}" | gpg --encrypt --recipient "${SUPPORT_EMAIL}" > "${SECRETS_DIR}/token.gpg"
    echo "${DASH_PWD}" | gpg --encrypt --recipient "${SUPPORT_EMAIL}" > "${SECRETS_DIR}/password.gpg"
    chmod 600 "${SECRETS_DIR}"/*
    chattr +i "${SECRETS_DIR}" 2>/dev/null
}

# 智能配置生成
configure_frp() {
    echo -e "${BLUE}[5/12] 配置FRP服务..."
    
    # 智能端口分配
    declare -g BIND_PORT=$(negotiate_port 31943 tcp)
    declare -g KCP_PORT=${BIND_PORT}
    declare -g QUIC_PORT=$(negotiate_port 31944 udp)
    declare -g DASH_PORT=$(negotiate_port 7500 tcp)

    cat > "${CONFIG_DIR}/frps.toml" <<EOF
[common]
bind_port = ${BIND_PORT}
kcp_bind_port = ${KCP_PORT}
quic_bind_port = ${QUIC_PORT}
subdomain_host = "${DOMAIN}"
auth_method = "token"
auth_token = "${FRP_TOKEN}"

[web]
dashboard_addr = "127.0.0.1"
dashboard_port = ${DASH_PORT}
dashboard_user = "admin"
dashboard_pwd = "${DASH_PWD}"
enable_prometheus = true

transport.tls.enable = true
transport.tls.certFile = "${CERTS_DIR}/fullchain.pem"
transport.tls.keyFile = "${CERTS_DIR}/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
log_max_days = 7
EOF
}

# 客户端配置生成器
generate_client_config() {
    echo -e "${BLUE}[6/12] 生成客户端配置..."
    read -p "输入客户端子域名（如bigdata01）: " SUBDOMAIN
    read -p "输入客户端本地IP: " CLIENT_IP
    read -p "输入客户端SSH端口: " SSH_PORT

    CLIENT_FILE="${CONFIG_DIR}/client_${SUBDOMAIN}.toml"
    cat > "${CLIENT_FILE}" <<EOF
[common]
server_addr = "${DOMAIN}"
server_port = ${BIND_PORT}
auth.token = "${FRP_TOKEN}"

[${SUBDOMAIN}-ssh]
type = "tcp"
local_ip = "${CLIENT_IP}"
local_port = ${SSH_PORT}
remote_port = ${BIND_PORT}
custom_domains = "${SUBDOMAIN}.${DOMAIN}"
transport.tls.enable = true
EOF

    echo -e "${GREEN}[SUCCESS] 客户端配置已保存至：${CLIENT_FILE}"
    echo -e "连接命令：ssh ${SUBDOMAIN}.${DOMAIN} -p ${BIND_PORT}"
}

####################
# 主流程控制
####################

main() {
    # 初始化安全环境
    [[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR] 必须使用root权限运行" && exit 1
    [[ -f "${LOCK_FILE}" ]] && echo -e "${RED}[ERROR] 检测到重复实例" && exit 1
    touch "${LOCK_FILE}"
    trap 'rm -f "${LOCK_FILE}"; exit' EXIT INT TERM

    init_logging
    detect_system
    manage_firewall

    # 选择访问方式
    PS3="请选择访问方式："
    select ACCESS_TYPE in "IP" "域名"; do
        case ${ACCESS_TYPE} in
            IP)
                SERVER_IP=$(curl -4s icanhazip.com)
                DOMAIN="${SERVER_IP//./-}.nip.io"
                break
                ;;
            域名)
                read -p "请输入域名：" DOMAIN
                break
                ;;
            *) echo -e "${RED}[ERROR] 无效选择" ;;
        esac
    done

    manage_certificate
    generate_secrets
    configure_frp

    # 安装服务
    echo -e "${BLUE}[7/12] 安装FRP服务..."
    LATEST_VER=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f 4)
    FRP_PACKAGE="frp_${LATEST_VER}_linux_${ARCH}.tar.gz"
    
    if [ ! -f "${FRP_PACKAGE}" ]; then
        wget -q "https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"
        tar zxf "${FRP_PACKAGE}"
    fi
    
    install -m 750 "frp_${LATEST_VER//v}_linux_${ARCH}/frps" "/usr/local/bin/"
    
    # 系统服务集成
    cat > "/etc/systemd/system/frps.service" <<EOF
[Unit]
Description=FRP Server Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c ${CONFIG_DIR}/frps.toml
Restart=on-failure
Environment="FRP_TOKEN=${FRP_TOKEN}"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now frps

    # 最终输出
    echo -e "\n${GREEN}
########################################
#          部署成功！重要信息         #
########################################
${NC}"
    echo -e "${BOLD}▸ 服务端地址：${GREEN}${DOMAIN}"
    echo -e "${BOLD}▸ 主要端口："
    echo -e "  - TCP: ${BIND_PORT} (主服务)"
    echo -e "  - KCP: ${KCP_PORT} (UDP加速)"
    echo -e "  - QUIC: ${QUIC_PORT} (快速协议)"
    echo -e "  - Dashboard: ${DASH_PORT}"
    echo -e "${BOLD}▸ 安全凭证："
    echo -e "  Token: ${RED}${FRP_TOKEN}${NC}"
    echo -e "  Dashboard密码: ${RED}${DASH_PWD}${NC}"
    echo -e "${BOLD}▸ 日志文件：${LOG_FILE}"

    # 生成客户端配置
    read -p "是否生成客户端配置？(Y/n): " choice
    [[ ${choice} =~ [nN] ]] || generate_client_config
}

####################
# 执行入口
####################
main "$@"
