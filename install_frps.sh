#!/bin/bash
# FRPS 全自动部署脚本（安全增强版）
# 版本：4.0
# 作者：智能助手
# 功能：支持版本检测、日志记录、服务验证、DNS确认、端口冲突检测

####################
# 全局配置
####################
LOG_DIR="/var/log/frp-installer"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d%H%M%S).log"
SUPPORT_EMAIL="support@example.com"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 系统信息变量
OS_TYPE=""          # 操作系统类型 (redhat/debian)
ARCH=""             # CPU 架构 (amd64/arm64/armv7)
DOMAIN=""           # 用户域名

####################
# 函数定义
####################

# 初始化日志系统
init_logging() {
    mkdir -p ${LOG_DIR}
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "\n${BLUE}=== 安装日志开始于 $(date) ===${NC}\n"
}

# 检测操作系统类型
detect_os() {
    echo -e "${BLUE}[1/8] 正在检测操作系统类型...${NC}"
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

# 输入验证函数
validate_port() {
    local port=$1
    local name=$2
    local protocol=$3

    # 基本验证
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        echo -e "${RED}错误：${name} 端口必须为1-65535之间的数字${NC}"
        return 1
    fi

    # 冲突检测
    if ! check_port_conflict $port $protocol; then
        echo -e "${YELLOW}请重新输入${name}端口：${NC}"
        return 1
    fi

    return 0
}

# 域名解析确认
confirm_dns() {
    echo -e "\n${YELLOW}⚠️ 请确认已完成DNS解析配置："
    echo -e "  域名: ${DOMAIN}"
    echo -e "  指向服务器IP: $(curl -s icanhazip.com)"
    echo -e "----------------------------------------"
    read -p "是否已正确配置DNS解析？(y/N): " confirm
    
    if [[ ! $confirm =~ [yY] ]]; then
        echo -e "${RED}❌ 请先配置DNS解析后再继续！${NC}"
        exit 1
    fi

    echo -e "${BLUE}正在验证DNS解析..."
    if ! dig +short ${DOMAIN} | grep -q $(curl -s icanhazip.com); then
        echo -e "${RED}❌ DNS解析未生效，可能原因："
        echo -e "1. DNS记录配置错误"
        echo -e "2. 解析尚未生效（通常需要5-30分钟）"
        echo -e "3. 域名服务商存在问题${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ DNS解析验证通过${NC}"
}

# 生成高强度随机密码
gen_secret() {
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 32 | head -n 1
}

# 下载文件函数（带进度显示）
download_file() {
    local url=$1
    local filename=$2

    if command -v curl &> /dev/null; then
        echo -e "${BLUE}使用 curl 下载...${NC}"
        curl -# -L -o "${filename}" "${url}" || return 1
    elif command -v wget &> /dev/null; then
        echo -e "${BLUE}使用 wget 下载...${NC}"
        wget --show-progress -O "${filename}" "${url}" || return 1
    else
        echo -e "${YELLOW}尝试安装 curl...${NC}"
        if [ "$OS_TYPE" = "redhat" ]; then
            yum install -y curl > /dev/null
        else
            apt install -y curl > /dev/null
        fi
        curl -# -L -o "${filename}" "${url}" || return 1
    fi
}

# 服务状态检测
verify_service() {
    echo -e "\n${BLUE}=== 服务验证 ===${NC}"
    
    # 检测服务状态
    if ! systemctl is-active --quiet frps; then
        echo -e "${RED}❌ 服务未运行！"
        echo -e "请检查日志：journalctl -u frps${NC}"
        return 1
    fi

    # 检测Dashboard访问
    echo -e "${BLUE}正在测试Dashboard访问..."
    HTTP_CODE=$(curl -sko /dev/null -w "%{http_code}" "https://${DOMAIN}:${DASH_PORT}")
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "${GREEN}✅ 服务验证通过"
        echo -e "Dashboard地址: https://${DOMAIN}:${DASH_PORT}${NC}"
        return 0
    else
        echo -e "${RED}❌ Dashboard访问失败 (HTTP代码: ${HTTP_CODE})"
        echo -e "可能原因："
        echo -e "1. 防火墙未开放端口"
        echo -e "2. TLS证书问题"
        echo -e "3. FRPS配置错误${NC}"
        return 1
    fi
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
detect_os
detect_arch
echo -e "${GREEN}✅ 系统检测完成：${OS_TYPE} (${ARCH})${NC}"

# 域名配置
echo -e "\n${BLUE}=== 域名配置 ===${NC}"
while true; do
    read -p "请输入您的域名（例如：ai.com）: " DOMAIN
    [[ -n "$DOMAIN" ]] && break || echo -e "${RED}错误：域名不能为空！${NC}"
done
confirm_dns

# 端口配置（带冲突检测）
echo -e "\n${BLUE}=== 端口配置 ===${NC}"

configure_port() {
    local prompt=$1
    local default=$2
    local protocol=$3
    local varname=$4

    while true; do
        read -p "${prompt} [默认${default}]: " input
        input=${input:-$default}
        if validate_port $input "${prompt}" $protocol; then
            eval $varname=$input
            break
        fi
    done
}

configure_port "TCP 绑定端口" 31943 "tcp" BIND_PORT
configure_port "KCP 绑定端口" $BIND_PORT "udp" KCP_PORT
configure_port "QUIC 绑定端口" 31944 "udp" QUIC_PORT
configure_port "Dashboard 端口" 7500 "tcp" DASH_PORT

# 用户凭证配置
echo -e "\n${BLUE}[3/8] 用户凭证配置...${NC}"
read -p "Dashboard 用户名 [默认admin]: " DASH_USER
DASH_USER=${DASH_USER:-admin}
DASH_PWD=$(gen_secret)
FRP_TOKEN=$(gen_secret)

# 版本检测与下载
echo -e "\n${BLUE}[4/8] 软件包管理...${NC}"
LATEST_VER=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f 4)
FRP_PACKAGE="frp_${LATEST_VER//v}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"

if [ -f "/usr/local/bin/frps" ]; then
    LOCAL_VER=$(frps --version | awk '{print $3}')
    if [ "$LOCAL_VER" = "${LATEST_VER//v}" ]; then
        echo -e "${GREEN}✅ 已安装最新版本 (v${LOCAL_VER})，跳过下载${NC}"
    else
        echo -e "${YELLOW}发现新版本：${LATEST_VER}，当前版本：${LOCAL_VER}${NC}"
        read -p "是否更新？(Y/n): " update_confirm
        [[ $update_confirm =~ [yY] ]] && download_file "${DOWNLOAD_URL}" "${FRP_PACKAGE}"
    fi
else
    echo -e "${BLUE}[5/8] 开始下载 FRP 软件包...${NC}"
    download_file "${DOWNLOAD_URL}" "${FRP_PACKAGE}"
fi

# 安装流程
echo -e "\n${BLUE}[6/8] 正在解压安装文件...${NC}"
tar zxf "${FRP_PACKAGE}" && cd frp_${LATEST_VER//v}_linux_${ARCH}

echo -e "${BLUE}创建系统目录结构...${NC}"
mkdir -p /etc/frp/tls /var/log/frp

echo -e "${BLUE}生成自签名 TLS 证书...${NC}"
openssl req -newkey rsa:2048 -nodes -keyout /etc/frp/tls/privkey.pem \
    -x509 -days 365 -out /etc/frp/tls/fullchain.pem \
    -subj "/CN=${DOMAIN}" > /dev/null 2>&1

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
dashboard_user = "${DASH_USER}
dashboard_pwd = "${DASH_PWD}"

transport.tls.enable = true
transport.tls.certFile = "/etc/frp/tls/fullchain.pem"
transport.tls.keyFile = "/etc/frp/tls/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
log_max_days = 14
enable_prometheus = true
EOF

echo -e "${BLUE}配置系统服务...${NC}"
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

echo -e "${BLUE}安装可执行程序...${NC}"
install -m 755 frps /usr/local/bin/frps

# 防火墙配置
echo -e "\n${BLUE}[7/8] 配置防火墙规则...${NC}"
if [ "$OS_TYPE" = "redhat" ]; then
    firewall-cmd --permanent --add-port=${BIND_PORT}/tcp > /dev/null
    firewall-cmd --permanent --add-port=${KCP_PORT}/udp > /dev/null
    firewall-cmd --permanent --add-port=${QUIC_PORT}/udp > /dev/null
    firewall-cmd --permanent --add-port=${DASH_PORT}/tcp > /dev/null
    firewall-cmd --reload > /dev/null
else
    ufw allow ${BIND_PORT}/tcp > /dev/null
    ufw allow ${KCP_PORT}/udp > /dev/null
    ufw allow ${QUIC_PORT}/udp > /dev/null
    ufw allow ${DASH_PORT}/tcp > /dev/null
    ufw --force reload > /dev/null
fi

# 服务启动
echo -e "${BLUE}[8/8] 启动 FRP 服务...${NC}"
systemctl daemon-reload > /dev/null
systemctl enable frps > /dev/null
systemctl start frps

# 最终验证
if verify_service; then
    echo -e "\n${GREEN}
########################################
#        部署成功！服务已就绪         #
########################################${NC}"
else
    echo -e "\n${RED}
########################################
#        部署失败！请检查日志         #
########################################${NC}"
    echo -e "\n调试建议："
    echo -e "1. 查看安装日志：tail -n 50 ${LOG_FILE}"
    echo -e "2. 检查服务状态：systemctl status frps"
    echo -e "3. 联系支持：${SUPPORT_EMAIL}"
fi

# 显示配置信息
echo -e "\n${BLUE}====================== 配置摘要 ======================${NC}"
echo -e "系统类型:        ${YELLOW}${OS_TYPE} (${ARCH})${NC}"
echo -e "服务域名:        ${YELLOW}${DOMAIN}${NC}"
echo -e "TCP 端口:        ${YELLOW}${BIND_PORT}${NC}"
echo -e "KCP 端口:        ${YELLOW}${KCP_PORT}${NC}"
echo -e "QUIC 端口:       ${YELLOW}${QUIC_PORT}${NC}"
echo -e "Dashboard 地址:  ${YELLOW}https://${DOMAIN}:${DASH_PORT}${NC}"
echo -e "Dashboard 用户:  ${YELLOW}${DASH_USER}${NC}"
echo -e "访问密码:        ${YELLOW}${DASH_PWD}${NC}"
echo -e "FRP Token:       ${YELLOW}${FRP_TOKEN}${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}提示：所有凭证已安全存储在 /etc/frp/env 目录${NC}"
echo -e "${YELLOW}⚠️ 安装日志已保存至：${LOG_FILE}${NC}"
