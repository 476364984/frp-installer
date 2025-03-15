#!/bin/bash
# FRPS 全自动部署脚本（安全增强版）
# 版本：6.0
# 功能：支持Let's Encrypt证书、多接入方式、客户端生成、智能DNS验证

####################
# 全局配置
####################
LOG_DIR="/var/log/frp-installer"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d%H%M%S).log"
CERTS_DIR="/etc/letsencrypt/live"
CONFIG_DIR="/etc/frp"
SUPPORT_EMAIL="support@example.com"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

####################
# 函数定义
####################

# 初始化日志系统
init_logging() {
    mkdir -p ${LOG_DIR}
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "\n${BLUE}=== 安装日志开始于 $(date) ===${NC}\n"
}

# 安装Certbot
install_certbot() {
    echo -e "${BLUE}[3/10] 安装Certbot...${NC}"
    if [ "$OS_TYPE" = "redhat" ]; then
        yum install -y epel-release
        yum install -y certbot
    else
        apt update
        apt install -y certbot
    fi
}

# DNS解析验证（改进版）
validate_dns() {
    local domain=$1
    local expected_ip=$2
    local retries=3
    local wait_time=30

    echo -e "${BLUE}[4/10] 验证DNS解析...${NC}"
    for ((i=1; i<=retries; i++)); do
        local dns_result
        dns_result=$(dig +short ${domain} | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
        
        if [ "$dns_result" = "$expected_ip" ]; then
            echo -e "${GREEN}✅ DNS解析验证成功：${domain} → ${dns_result}${NC}"
            return 0
        fi

        echo -e "${YELLOW}⚠️ 第${i}次验证失败，期望IP：${expected_ip}，实际检测到：${dns_result:-无记录}"
        if [ $i -lt $retries ]; then
            echo -e "等待${wait_time}秒后重试...${NC}"
            sleep $wait_time
        fi
    done

    echo -e "${RED}❌ DNS解析验证失败！可能原因："
    echo -e "1. DNS记录配置错误"
    echo -e "2. 解析尚未生效（通常需要5-30分钟）"
    echo -e "3. 域名服务商存在问题${NC}"
    exit 1
}

# 端口冲突检测
check_port_conflict() {
    local port=$1
    local protocol=$2
    
    echo -e "${BLUE}正在检测端口 ${port}/${protocol}..."
    if ss -tuln | grep -q ":${port} "; then
        echo -e "${RED}❌ 端口冲突：${port}/${protocol} 已被以下进程占用："
        ss -tulp | grep ":${port} "
        echo -e "${NC}"
        return 1
    fi
    return 0
}

# 生成客户端配置
generate_client_config() {
    echo -e "\n${GREEN}=== 客户端配置生成向导 ===${NC}"
    read -p "请输入客户端名称（例如 office-pc）: " CLIENT_NAME
    read -p "请输入服务类型（ssh/web/other）: " SERVICE_TYPE
    read -p "请输入本地服务端口: " LOCAL_PORT
    read -p "请输入自定义子域名前缀（例如 bigdata01）: " SUBDOMAIN

    CLIENT_CONFIG="${CONFIG_DIR}/client/${CLIENT_NAME}.ini"
    mkdir -p ${CONFIG_DIR}/client

    cat > ${CLIENT_CONFIG} <<EOF
[common]
server_addr = ${DOMAIN}
server_port = ${BIND_PORT}
auth_token = ${FRP_TOKEN}

[${SUBDOMAIN}]
type = tcp
local_ip = 127.0.0.1
local_port = ${LOCAL_PORT}
remote_port = ${LOCAL_PORT}
subdomain = ${SUBDOMAIN}
EOF

    echo -e "${GREEN}✅ 客户端配置已生成：${CLIENT_CONFIG}"
    echo -e "使用命令连接：frpc -c ${CLIENT_CONFIG}${NC}"
}

####################
# 主程序
####################

# 初始化日志
init_logging

# 显示欢迎信息
echo -e "${GREEN}
########################################
#       FRP 服务端自动化安装程序       #
########################################
${NC}"

# 用户确认
read -p "是否继续安装？(Y/n): " confirm
[[ ! $confirm =~ [yY] ]] && exit

# 系统检测
echo -e "${BLUE}[1/10] 系统环境检测...${NC}"
if [ -f /etc/os-release ]; then
    source /etc/os-release
    case ${ID} in
        centos|rhel|fedora|almalinux|rocky)
            OS_TYPE="redhat"
            ;;
        debian|ubuntu|linuxmint)
            OS_TYPE="debian"
            ;;
        *)
            echo -e "${RED}不支持的 Linux 发行版: ${ID}${NC}"
            exit 1
            ;;
    esac
else
    echo -e "${RED}无法检测操作系统类型${NC}"
    exit 1
fi

ARCH=$(uname -m)
case ${ARCH} in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
    *)
        echo -e "${RED}不支持的 CPU 架构: ${ARCH}${NC}"
        exit 1
        ;;
esac

# Dashboard配置
echo -e "${BLUE}[2/10] 服务配置...${NC}"
echo -e "${YELLOW}请选择Dashboard访问方式："
echo "1) 使用主域名访问（需已解析）"
echo "2) 使用独立子域名访问（例如 dashboard.yourdomain.com）"
read -p "请输入选择 [1/2]: " DASHBOARD_TYPE

if [ "$DASHBOARD_TYPE" = "1" ]; then
    read -p "请输入主域名（例如 frp.example.com）: " DOMAIN
    DASH_DOMAIN=$DOMAIN
else
    read -p "请输入主域名（用于客户端连接）: " DOMAIN
    read -p "请输入Dashboard专用子域名: " DASH_DOMAIN
fi

# 获取服务器IP
echo -e "${BLUE}获取服务器公网IP...${NC}"
SERVER_IP=$(curl -4 -s --connect-timeout 10 ifconfig.co || curl -4 -s ipinfo.io/ip)
[ -z "$SERVER_IP" ] && { echo -e "${RED}❌ 无法获取服务器IP${NC}"; exit 1; }

# DNS验证
validate_dns $DOMAIN $SERVER_IP
[ "$DASHBOARD_TYPE" = "2" ] && validate_dns $DASH_DOMAIN $SERVER_IP

# 证书配置
read -p "请输入管理员邮箱： " EMAIL
install_certbot

echo -e "${BLUE}[5/10] 申请SSL证书...${NC}"
certbot certonly --standalone --agree-tos --non-interactive \
    -d ${DASH_DOMAIN} \
    -m ${EMAIL} \
    --pre-hook "systemctl stop frps" \
    --post-hook "systemctl start frps"

# 端口配置
echo -e "${BLUE}[6/10] 端口配置...${NC}"
configure_port() {
    while true; do
        read -p "$1 [默认$2]: " port
        port=${port:-$2}
        if [[ "$port" =~ ^[0-9]+$ ]] && [ $port -ge 1 -a $port -le 65535 ]; then
            if check_port_conflict $port $3; then
                eval $4=$port
                break
            fi
        else
            echo -e "${RED}无效端口号！${NC}"
        fi
    done
}

configure_port "TCP绑定端口" 31943 tcp BIND_PORT
configure_port "KCP绑定端口" $BIND_PORT udp KCP_PORT
configure_port "QUIC绑定端口" 31944 udp QUIC_PORT
configure_port "Dashboard端口" 7500 tcp DASH_PORT

# 生成凭证
echo -e "${BLUE}[7/10] 生成安全凭证...${NC}"
FRP_TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
DASH_PWD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 32 | head -n 1)
DASH_USER=${DASH_USER:-admin}

# 下载安装FRP
echo -e "${BLUE}[8/10] 下载FRP...${NC}"
LATEST_VER=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f 4)
FRP_PACKAGE="frp_${LATEST_VER//v}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"

if [ -f "/usr/local/bin/frps" ]; then
    LOCAL_VER=$(frps --version | awk '{print $3}')
    if [ "$LOCAL_VER" != "${LATEST_VER//v}" ]; then
        download_file "${DOWNLOAD_URL}" "${FRP_PACKAGE}"
    fi
else
    download_file "${DOWNLOAD_URL}" "${FRP_PACKAGE}"
fi

tar zxf "${FRP_PACKAGE}" && cd frp_${LATEST_VER//v}_linux_${ARCH}

# 配置文件
echo -e "${BLUE}[9/10] 生成配置文件...${NC}"
mkdir -p ${CONFIG_DIR}/{tls,env}
cat > ${CONFIG_DIR}/frps.toml <<EOF
[common]
bind_port = ${BIND_PORT}
kcp_bind_port = ${KCP_PORT}
quic_bind_port = ${QUIC_PORT}
subdomain_host = "${DOMAIN}"

auth_method = "token"
auth_token = "${FRP_TOKEN}"

[webServer]
dashboard_addr = "0.0.0.0"
dashboard_port = ${DASH_PORT}
dashboard_user = "${DASH_USER}"
dashboard_pwd = "${DASH_PWD}"

transport.tls.enable = true
transport.tls.certFile = "${CERTS_DIR}/${DASH_DOMAIN}/fullchain.pem"
transport.tls.keyFile = "${CERTS_DIR}/${DASH_DOMAIN}/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
log_max_days = 14
enable_prometheus = true
EOF

# 系统服务配置
echo -e "${BLUE}[10/10] 配置系统服务...${NC}"
cat > /etc/systemd/system/frps.service <<EOF
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

install -m 755 frps /usr/local/bin/frps

# 防火墙配置
if [ "$OS_TYPE" = "redhat" ]; then
    firewall-cmd --permanent --add-port=${BIND_PORT}/tcp
    firewall-cmd --permanent --add-port=${DASH_PORT}/tcp
    firewall-cmd --reload
else
    ufw allow ${BIND_PORT}/tcp
    ufw allow ${DASH_PORT}/tcp
    ufw --force reload
fi

# 启动服务
systemctl daemon-reload
systemctl enable frps
systemctl start frps

# 验证部署
echo -e "\n${BLUE}=== 部署验证 ===${NC}"
sleep 3
if systemctl is-active --quiet frps; then
    echo -e "${GREEN}✅ 服务已成功运行！"
    echo -e "Dashboard地址: https://${DASH_DOMAIN}:${DASH_PORT}"
    echo -e "访问令牌: ${FRP_TOKEN}${NC}"
else
    echo -e "${RED}❌ 服务启动失败，请检查日志："
    echo -e "1. journalctl -u frps"
    echo -e "2. 查看安装日志: ${LOG_FILE}${NC}"
    exit 1
fi

# 生成客户端配置
read -p "是否要生成客户端配置？(Y/n): " gen_client
[[ $gen_client =~ [nN] ]] || generate_client_config

echo -e "\n${GREEN}=== 安装完成！ ==="
echo -e "安装日志: ${LOG_FILE}"
echo -e "配置文件: ${CONFIG_DIR}/frps.toml"
echo -e "客户端配置目录: ${CONFIG_DIR}/client/${NC}"
