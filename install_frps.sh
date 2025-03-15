#!/bin/bash
# FRPS 全自动部署脚本（安全增强版）
# 版本：7.1
# 功能：支持IP/域名访问、OpenSSL证书、客户端配置提示、完整系统检测

####################
# 全局配置
####################
LOG_DIR="/var/log/frp-installer"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d%H%M%S).log"
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

# 检测操作系统
detect_os() {
    echo -e "${BLUE}[1/10] 检测操作系统...${NC}"
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
                echo -e "${RED}❌ 不支持的Linux发行版: ${ID}${NC}"
                exit 1
                ;;
        esac
        echo -e "${GREEN}✅ 检测到系统类型: ${OS_TYPE}${NC}"
    else
        echo -e "${RED}❌ 无法检测操作系统类型${NC}"
        exit 1
    fi
}

# 检测CPU架构
detect_arch() {
    echo -e "${BLUE}[2/10] 检测CPU架构...${NC}"
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *)
            echo -e "${RED}❌ 不支持的CPU架构: ${ARCH}${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}✅ 检测到CPU架构: ${ARCH}${NC}"
}

# 生成自签名证书
generate_ssl_cert() {
    local domain=$1
    echo -e "${BLUE}[4/10] 生成SSL证书...${NC}"
    mkdir -p ${CONFIG_DIR}/tls
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout ${CONFIG_DIR}/tls/privkey.pem \
        -out ${CONFIG_DIR}/tls/fullchain.pem \
        -subj "/CN=${domain}" \
        -addext "subjectAltName=DNS:${domain}" 2>/dev/null
    
    # 设置证书权限
    chmod 600 ${CONFIG_DIR}/tls/*
    echo -e "${GREEN}✅ 证书已生成: ${CONFIG_DIR}/tls/{privkey,fullchain}.pem${NC}"
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
    
    # 输入配置参数
    read -p "请输入客户端名称（例如 office-pc）: " CLIENT_NAME
    read -p "请输入服务类型（ssh/web/other）: " SERVICE_TYPE
    read -p "请输入本地服务IP（默认127.0.0.1）: " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-127.0.0.1}
    
    while true; do
        read -p "请输入本地服务端口: " LOCAL_PORT
        [[ $LOCAL_PORT =~ ^[0-9]+$ ]] && break
        echo -e "${RED}端口必须是数字！${NC}"
    done
    
    read -p "请输入自定义子域名前缀（例如 bigdata01）: " SUBDOMAIN
    
    # 设置保存路径
    DEFAULT_SAVE_PATH="${CONFIG_DIR}/client/${CLIENT_NAME}.ini"
    read -p "请输入保存路径（默认 ${DEFAULT_SAVE_PATH}）: " SAVE_PATH
    SAVE_PATH=${SAVE_PATH:-$DEFAULT_SAVE_PATH}
    mkdir -p $(dirname "$SAVE_PATH")
    
    # 生成配置文件
    cat > "$SAVE_PATH" <<EOF
[common]
server_addr = ${SERVER_ADDR}
server_port = ${BIND_PORT}
auth_token = ${FRP_TOKEN}

[${SUBDOMAIN}]
type = tcp
local_ip = ${LOCAL_IP}
local_port = ${LOCAL_PORT}
remote_port = ${LOCAL_PORT}
subdomain = ${SUBDOMAIN}
EOF

    echo -e "${GREEN}✅ 客户端配置已保存至：${SAVE_PATH}"
    echo -e "使用命令启动：${YELLOW}frpc -c ${SAVE_PATH}${NC}"
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
[[ $confirm =~ [nN] ]] && exit

# 系统检测
detect_os
detect_arch

# 选择访问方式
echo -e "${BLUE}[3/10] 选择访问方式...${NC}"
echo -e "${YELLOW}请选择Dashboard访问类型："
echo "1) 使用IP地址访问（自动生成nip.io域名）"
echo "2) 使用域名访问"
read -p "请输入选择 [1/2]: " ACCESS_TYPE

# 获取服务器IP
SERVER_IP=$(curl -4 -s --connect-timeout 10 icanhazip.com || echo "127.0.0.1")
if [ "$ACCESS_TYPE" = "1" ]; then
    NIPIO_DOMAIN="${SERVER_IP//./-}.nip.io"
    DOMAIN=${NIPIO_DOMAIN}
    SERVER_ADDR=${SERVER_IP}
    echo -e "${GREEN}使用IP访问模式，生成域名：${DOMAIN}${NC}"
else
    while true; do
        read -p "请输入您的域名（例如 frp.example.com）: " DOMAIN
        [[ -n "$DOMAIN" ]] && break
        echo -e "${RED}域名不能为空！${NC}"
    done
    SERVER_ADDR=${DOMAIN}
fi

# 生成SSL证书
generate_ssl_cert ${DOMAIN}

# 端口配置
echo -e "${BLUE}[5/10] 端口配置...${NC}"
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
configure_port "Dashboard端口" 7500 tcp DASH_PORT

# 生成凭证
echo -e "${BLUE}[6/10] 生成安全凭证...${NC}"
FRP_TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
DASH_USER="admin"
DASH_PWD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 16 | head -n 1)

# 下载安装FRP
echo -e "${BLUE}[7/10] 下载安装FRP...${NC}"
LATEST_VER=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f 4)
FRP_PACKAGE="frp_${LATEST_VER//v}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"

if ! curl -LO --progress-bar "${DOWNLOAD_URL}"; then
    echo -e "${RED}❌ 下载失败，请检查："
    echo -e "1. 网络连接状态"
    echo -e "2. 版本号有效性：${LATEST_VER}"
    echo -e "3. 下载地址：${DOWNLOAD_URL}${NC}"
    exit 1
fi

tar zxf ${FRP_PACKAGE} && cd frp_${LATEST_VER//v}_linux_${ARCH}

# 配置文件
echo -e "${BLUE}[8/10] 生成配置文件...${NC}"
mkdir -p ${CONFIG_DIR}/client
cat > ${CONFIG_DIR}/frps.toml <<EOF
[common]
bind_port = ${BIND_PORT}
auth_token = ${FRP_TOKEN}

[webServer]
dashboard_addr = "0.0.0.0"
dashboard_port = ${DASH_PORT}
dashboard_user = "${DASH_USER}"
dashboard_pwd = "${DASH_PWD}"

transport.tls.enable = true
transport.tls.certFile = "${CONFIG_DIR}/tls/fullchain.pem"
transport.tls.keyFile = "${CONFIG_DIR}/tls/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
EOF

# 安装服务
echo -e "${BLUE}[9/10] 配置系统服务...${NC}"
install -m 755 frps /usr/local/bin/frps

cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c ${CONFIG_DIR}/frps.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable frps
systemctl start frps

# 显示安装结果
echo -e "\n${GREEN}
########################################
#          安装成功！重要信息         #
########################################
${NC}"

echo -e "${YELLOW}▸ 服务端地址：${GREEN}${SERVER_ADDR}${NC}"
echo -e "${YELLOW}▸ CPU架构：${GREEN}${ARCH}${NC}"
echo -e "${YELLOW}▸ 操作系统：${GREEN}${OS_TYPE}${NC}"
echo -e "${YELLOW}▸ TCP绑定端口：${GREEN}${BIND_PORT}${NC}"
echo -e "${YELLOW}▸ Dashboard访问地址：${GREEN}https://${DOMAIN}:${DASH_PORT}${NC}"
echo -e "${YELLOW}▸ Dashboard用户名：${GREEN}${DASH_USER}${NC}"
echo -e "${YELLOW}▸ Dashboard密码：${GREEN}${DASH_PWD}${NC}"
echo -e "${YELLOW}▸ FRP Token：${GREEN}${FRP_TOKEN}${NC}"
echo -e "${YELLOW}▸ 客户端配置目录：${GREEN}${CONFIG_DIR}/client/${NC}"
echo -e "${YELLOW}▸ 安装日志文件：${GREEN}${LOG_FILE}${NC}"

# 生成客户端配置
read -p "是否生成客户端配置文件？(Y/n): " gen_client
[[ $gen_client =~ [nN] ]] || generate_client_config

echo -e "\n${GREEN}提示："
echo -e "1. 防火墙需要开放端口：${BIND_PORT}/TCP 和 ${DASH_PORT}/TCP"
echo -e "2. 客户端使用示例：frpc -c /path/to/config.ini"
echo -e "3. 查看服务状态：systemctl status frps${NC}"
