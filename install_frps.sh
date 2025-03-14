#!/bin/bash
# FRPS 全自动部署脚本（安全增强版）
# 版本：2.1
# 作者：Ai
# 功能：自动化部署 FRP 服务端，支持多架构、多发行版、安全增强配置

####################
# 全局变量定义部分
####################
# 颜色定义用于美化输出
RED='\033[0;31m'    # 错误/警告消息
GREEN='\033[0;32m'  # 成功消息
YELLOW='\033[0;33m' # 提示信息
BLUE='\033[0;34m'   # 状态消息
NC='\033[0m'        # 恢复默认颜色

# 系统信息变量
OS_TYPE=""          # 操作系统类型 (redhat/debian)
PKG_MGR=""          # 包管理器 (yum/apt)
FIREWALL_CMD=""     # 防火墙命令 (firewall-cmd/ufw)
ARCH=""             # CPU 架构 (amd64/arm64/armv7)
DOMAIN=""           # 用户域名
BIND_PORT=31943     # TCP 绑定端口（默认值）
DASH_PORT=7500      # Dashboard 端口（默认值）

####################
# 函数定义部分
####################

# 检测操作系统类型和包管理器
detect_os() {
    echo -e "${BLUE}[1/8] 正在检测操作系统类型...${NC}"
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        case ${ID} in
            centos|rhel|fedora|almalinux|rocky)
                OS_TYPE="redhat"
                PKG_MGR="yum"
                FIREWALL_CMD="firewall-cmd"
                ;;
            debian|ubuntu|linuxmint)
                OS_TYPE="debian"
                PKG_MGR="apt"
                FIREWALL_CMD="ufw"
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
}

# 检测 CPU 架构
detect_arch() {
    echo -e "${BLUE}[2/8] 正在检测 CPU 架构...${NC}"
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
}

# 输入验证函数
validate_input() {
    local value=$1
    local name=$2
    local min=$3
    local max=$4

    # 空值检查
    if [[ -z "$value" ]]; then
        echo -e "${RED}错误：${name} 不能为空！${NC}"
        return 1
    fi

    # 数字格式检查
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误：${name} 必须为数字！${NC}"
        return 1
    fi

    # 数值范围检查
    if (( value < min || value > max )); then
        echo -e "${RED}错误：${name} 必须在 ${min}-${max} 之间！${NC}"
        return 1
    fi

    return 0
}

# 下载文件函数（带进度显示）
download_file() {
    local url=$1
    local filename=$2

    # 优先使用 curl 下载
    if command -v curl &> /dev/null; then
        echo -e "${BLUE}使用 curl 下载...${NC}"
        curl -# -L -o "${filename}" "${url}" || return 1
    # 其次使用 wget 下载
    elif command -v wget &> /dev/null; then
        echo -e "${BLUE}使用 wget 下载...${NC}"
        wget --show-progress -O "${filename}" "${url}" || return 1
    else
        # 如果没有下载工具则尝试自动安装
        echo -e "${YELLOW}未找到下载工具，尝试安装 curl...${NC}"
        ${PKG_MGR} install -y curl > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            curl -# -L -o "${filename}" "${url}" || return 1
        else
            echo -e "${RED}无法自动安装 curl，请手动安装后重试${NC}"
            return 1
        fi
    fi
}

# 生成高强度随机密码
gen_secret() {
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 32 | head -n 1
}

####################
# 主程序执行部分
####################

# 初始化系统检测
detect_os
detect_arch
echo -e "${GREEN}✅ 系统检测完成：${OS_TYPE} (${ARCH})${NC}"

# 用户输入处理
echo -e "\n${BLUE}=== 开始配置 FRP 服务端 ===${NC}"

# 域名输入（必需）
while true; do
    read -p "请输入您的域名（例如：ai.com）: " DOMAIN
    [[ -n "$DOMAIN" ]] && break || echo -e "${RED}错误：域名不能为空！${NC}"
done

# 端口配置（带智能默认值）
read -p "TCP 绑定端口 [默认31943]: " BIND_PORT
BIND_PORT=${BIND_PORT:-31943}

read -p "KCP 绑定端口 [同TCP端口]: " KCP_PORT
KCP_PORT=${KCP_PORT:-$BIND_PORT}

read -p "QUIC 绑定端口 [默认31944]: " QUIC_PORT
QUIC_PORT=${QUIC_PORT:-31944}

# Dashboard 配置
read -p "Dashboard 端口 [默认7500]: " DASH_PORT
DASH_PORT=${DASH_PORT:-7500}

read -p "Dashboard 用户名 [默认admin]: " DASH_USER
DASH_USER=${DASH_USER:-admin}

# 输入验证
echo -e "${BLUE}[3/8] 正在验证输入参数...${NC}"
validate_input $BIND_PORT "TCP 端口" 1 65535 || exit 1
validate_input $KCP_PORT "KCP 端口" 1 65535 || exit 1
validate_input $QUIC_PORT "QUIC 端口" 1 65535 || exit 1
validate_input $DASH_PORT "Dashboard 端口" 1 65535 || exit 1

# 生成安全凭证
echo -e "${BLUE}[4/8] 正在生成安全凭证...${NC}"
FRP_TOKEN=$(gen_secret)
DASH_PWD=$(gen_secret)

# 下载最新 FRP 版本
echo -e "\n${BLUE}[5/8] 正在获取最新版本信息...${NC}"
LATEST_VER=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f 4)
FRP_PACKAGE="frp_${LATEST_VER//v}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"

echo -e "${BLUE}[6/8] 开始下载 FRP 软件包...${NC}"
if ! download_file "${DOWNLOAD_URL}" "${FRP_PACKAGE}"; then
    echo -e "${RED}下载失败，请检查："
    echo -e "1. 网络连接状态"
    echo -e "2. 版本号有效性：${LATEST_VER}"
    echo -e "3. 下载地址：${DOWNLOAD_URL}${NC}"
    exit 1
fi

# 显示下载文件信息
echo -e "\n${GREEN}✓ 下载完成！文件校验信息：${NC}"
file_info=$(file "${FRP_PACKAGE}")
file_size=$(du -h "${FRP_PACKAGE}" | cut -f1)
echo -e "文件类型: ${YELLOW}${file_info#*: }${NC}"
echo -e "文件大小: ${YELLOW}${file_size}${NC}"

# 解压并安装
echo -e "\n${BLUE}[7/8] 正在解压安装文件...${NC}"
tar zxf "${FRP_PACKAGE}" && cd frp_${LATEST_VER//v}_linux_${ARCH}

# 准备系统目录
echo -e "${BLUE}创建系统目录结构...${NC}"
mkdir -p /etc/frp/tls /var/log/frp

# 生成 TLS 证书
echo -e "${BLUE}生成自签名 TLS 证书...${NC}"
openssl req -newkey rsa:2048 -nodes -keyout /etc/frp/tls/privkey.pem \
    -x509 -days 365 -out /etc/frp/tls/fullchain.pem \
    -subj "/CN=${DOMAIN}" > /dev/null 2>&1

# 生成配置文件
echo -e "${BLUE}生成配置文件...${NC}"
cat > /etc/frp/frps.toml <<EOF
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
transport.tls.certFile = "/etc/frp/tls/fullchain.pem"
transport.tls.keyFile = "/etc/frp/tls/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
log_max_days = 14

enable_prometheus = true
EOF

# 安全存储凭证
echo -e "${BLUE}安全存储访问凭证...${NC}"
mkdir -p /etc/frp/env
echo "${FRP_TOKEN}" > /etc/frp/env/frp_token
echo "${DASH_PWD}" > /etc/frp/env/dashboard_pwd
chmod 600 /etc/frp/env/*

# 配置系统服务
echo -e "${BLUE}创建 systemd 服务...${NC}"
cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
Restart=on-failure
Environment="FRP_TOKEN=${FRP_TOKEN}"
Environment="DASH_PWD=${DASH_PWD}"

[Install]
WantedBy=multi-user.target
EOF

# 安装可执行文件
echo -e "${BLUE}安装可执行程序...${NC}"
install -m 755 frps /usr/local/bin/frps

# 配置防火墙
echo -e "\n${BLUE}[8/8] 配置防火墙规则...${NC}"
case ${OS_TYPE} in
    redhat)
        firewall-cmd --permanent --add-port=${BIND_PORT}/tcp > /dev/null
        firewall-cmd --permanent --add-port=${KCP_PORT}/udp > /dev/null
        firewall-cmd --permanent --add-port=${QUIC_PORT}/udp > /dev/null
        firewall-cmd --permanent --add-port=${DASH_PORT}/tcp > /dev/null
        firewall-cmd --reload > /dev/null
        ;;
    debian)
        ufw allow ${BIND_PORT}/tcp > /dev/null
        ufw allow ${KCP_PORT}/udp > /dev/null
        ufw allow ${QUIC_PORT}/udp > /dev/null
        ufw allow ${DASH_PORT}/tcp > /dev/null
        ufw --force reload > /dev/null
        ;;
esac

# 启动服务
echo -e "${BLUE}启动 FRP 服务...${NC}"
systemctl daemon-reload > /dev/null
systemctl enable frps > /dev/null
systemctl start frps

# 显示最终配置信息
clear
echo -e "${GREEN}✅ FRP 服务部署完成！${NC}"
echo "====================== 配置摘要 ======================"
echo -e "系统类型:        ${YELLOW}${OS_TYPE} (${ARCH})${NC}"
echo -e "服务域名:        ${YELLOW}${DOMAIN}${NC}"
echo -e "TCP 端口:        ${YELLOW}${BIND_PORT}${NC}"
echo -e "KCP 端口:        ${YELLOW}${KCP_PORT}${NC}"
echo -e "QUIC 端口:       ${YELLOW}${QUIC_PORT}${NC}"
echo -e "Dashboard 地址:  ${YELLOW}https://${DOMAIN}:${DASH_PORT}${NC}"
echo -e "Dashboard 用户:  ${YELLOW}${DASH_USER}${NC}"
echo -e "访问密码:        ${YELLOW}${DASH_PWD}${NC}"
echo -e "FRP Token:       ${YELLOW}${FRP_TOKEN}${NC}"
echo "====================================================="
echo -e "${GREEN}提示：所有凭证已安全存储在 /etc/frp/env 目录${NC}"
echo -e "${BLUE}验证命令：systemctl status frps${NC}"
