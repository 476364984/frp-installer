#!/bin/bash
# FRPS 全自动部署脚本（终极整合增强版）
# 版本：15.0
# 功能：智能端口冲突处理、防火墙自动检测、安全增强、交互式配置

####################
# 全局配置
####################
LOG_DIR="/var/log/frp-installer"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d%H%M%S).log"
CONFIG_DIR="/etc/frp"
CERTS_DIR="${CONFIG_DIR}/tls"
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
    mkdir -p "${LOG_DIR}"
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "\n${BLUE}=== 安装日志开始于 $(date) ===${NC}\n"
}

# 致命错误处理
fatal_error() {
    echo -e "\n${RED}❌ 致命错误：$1${NC}"
    echo -e "${YELLOW}查看日志：${LOG_FILE}${NC}"
    exit 1
}

# 系统检测
detect_system() {
    echo -e "${BLUE}[1/15] 检测系统环境..."
    
    # 操作系统检测
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
            *) fatal_error "不支持的Linux发行版: ${ID}" ;;
        esac
    else
        fatal_error "无法识别操作系统"
    fi
    echo -e "${GREEN}✅ 操作系统: ${OS_TYPE}${NC}"

    # CPU架构检测
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *) fatal_error "不支持的CPU架构: ${ARCH}" ;;
    esac
    echo -e "${GREEN}✅ CPU架构: ${ARCH}${NC}"
}

# 安装必要依赖
install_dependencies() {
    echo -e "${BLUE}[2/15] 安装系统依赖..."
    case ${OS_TYPE} in
        redhat)
            yum install -y curl openssl openssl-devel firewalld \
                || fatal_error "依赖安装失败"
            systemctl enable --now firewalld \
                || echo -e "${YELLOW}⚠️ 防火墙启动失败，但继续安装...${NC}"
            ;;
        debian)
            apt update && apt install -y curl openssl ufw \
                || fatal_error "依赖安装失败"
            ufw --force enable || true
            ;;
    esac
}

# 增强版端口冲突检测
check_port_conflict() {
    local port=$1
    local protocol=$2
    
    echo -e "${BLUE}检测端口 ${port}/${protocol}..."
    conflict_info=$(ss -tulp | grep ":${port} ")
    if [ -n "$conflict_info" ]; then
        echo -e "${RED}❌ 端口冲突："
        echo "$conflict_info"
        return 1
    fi
    return 0
}

# 智能端口配置（带冲突处理）
configure_port() {
    local prompt=$1
    local default_port=$2
    local protocol=$3
    local varname=$4
    
    while true; do
        read -p "${prompt} [默认${default_port}]: " input_port
        port=${input_port:-$default_port}
        
        # 基础验证
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ $port -lt 1 -o $port -gt 65535 ]; then
            echo -e "${RED}错误：端口必须是1-65535之间的数字${NC}"
            continue
        fi

        # 检测端口冲突
        if check_port_conflict $port $protocol; then
            echo -e "${GREEN}✅ 端口 ${port}/${protocol} 可用${NC}"
            eval $varname=$port
            break
        else
            echo -e "${YELLOW}⚠️ 端口冲突处理选项："
            echo "1) 终止占用进程并继续使用此端口"
            echo "2) 重新输入其他端口"
            echo "3) 放弃安装"
            read -p "请选择处理方式 [1/2/3]: " conflict_choice
            
            case $conflict_choice in
                1)
                    # 获取进程信息
                    local pid=$(ss -tulp | grep ":${port} " | awk '{print $NF}' | cut -d= -f2 | sort -u)
                    if [ -n "$pid" ]; then
                        echo -e "${YELLOW}正在终止进程 PID: ${pid}..."
                        kill -9 $pid 2>/dev/null
                        sleep 1
                        if check_port_conflict $port $protocol; then
                            echo -e "${GREEN}✅ 进程已终止，端口 ${port}/${protocol} 可用${NC}"
                            eval $varname=$port
                            break
                        else
                            echo -e "${RED}❌ 进程终止失败，请手动处理${NC}"
                        fi
                    else
                        echo -e "${RED}❌ 无法获取进程信息，请手动处理${NC}"
                    fi
                    ;;
                2)
                    continue
                    ;;
                3)
                    echo -e "${RED}安装已中止${NC}"
                    exit 1
                    ;;
                *)
                    echo -e "${RED}无效选择，请重新输入${NC}"
                    ;;
            esac
        fi
    done
}

# 生成SSL证书
generate_cert() {
    echo -e "${BLUE}[3/15] 生成SSL证书..."
    mkdir -p "${CERTS_DIR}"
    
    if [ "${ACCESS_TYPE}" = "1" ]; then
        DOMAIN="${SERVER_IP//./-}.nip.io"
    fi

    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "${CERTS_DIR}/privkey.pem" \
        -out "${CERTS_DIR}/fullchain.pem" \
        -subj "/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null \
        || fatal_error "证书生成失败"

    chmod 600 "${CERTS_DIR}"/*
    echo -e "${GREEN}✅ 证书生成成功：${CERTS_DIR}/"
}

# 检测防火墙状态
check_firewall_status() {
    case ${OS_TYPE} in
        redhat)
            if systemctl is-active firewalld &>/dev/null; then
                echo -e "${GREEN}检测到 firewalld 正在运行${NC}"
                return 0
            else
                echo -e "${YELLOW}firewalld 未运行，跳过端口配置${NC}"
                return 1
            fi
            ;;
        debian)
            if dpkg -l ufw | grep -q '^ii' && ufw status | grep -q 'Status: active'; then
                echo -e "${GREEN}检测到 ufw 正在运行${NC}"
                return 0
            else
                echo -e "${YELLOW}ufw 未启用，跳过端口配置${NC}"
                return 1
            fi
            ;;
    esac
}

# 智能防火墙配置
configure_firewall() {
    echo -e "${BLUE}[4/15] 检测防火墙状态..."
    
    if ! check_firewall_status; then
        echo -e "${YELLOW}⚠️ 跳过防火墙配置${NC}"
        return 0
    fi

    echo -e "${BLUE}配置防火墙规则..."
    case ${OS_TYPE} in
        redhat)
            echo -e "${GREEN}添加防火墙规则..."
            firewall-cmd --permanent \
                --add-port=${BIND_PORT}/tcp \
                --add-port=${KCP_PORT}/udp \
                --add-port=${QUIC_PORT}/udp \
                --add-port=${DASH_PORT}/tcp \
                || echo -e "${YELLOW}⚠️ 端口添加失败，可能已存在相同规则${NC}"
            
            echo -e "${GREEN}重载防火墙配置..."
            firewall-cmd --reload || fatal_error "防火墙重载失败"
            ;;
        debian)
            echo -e "${GREEN}添加UFW规则..."
            ufw allow ${BIND_PORT}/tcp \
                || echo -e "${YELLOW}⚠️ TCP端口规则可能已存在${NC}"
            ufw allow ${KCP_PORT}/udp \
                || echo -e "${YELLOW}⚠️ KCP端口规则可能已存在${NC}"
            ufw allow ${QUIC_PORT}/udp \
                || echo -e "${YELLOW}⚠️ QUIC端口规则可能已存在${NC}"
            ufw allow ${DASH_PORT}/tcp \
                || echo -e "${YELLOW}⚠️ Dashboard端口规则可能已存在${NC}"
            
            echo -e "${GREEN}重载防火墙..."
            ufw reload || fatal_error "防火墙重载失败"
            ;;
    esac
    echo -e "${GREEN}✅ 防火墙规则更新成功"
}

# 版本检测与智能下载
smart_download() {
    get_latest_version
    FRP_PACKAGE="frp_${LATEST_VER//v}_linux_${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_VER}/${FRP_PACKAGE}"

    if check_local_version; then
        if [ "${LOCAL_VER}" = "${LATEST_VER//v}" ]; then
            echo -e "${GREEN}✅ 已是最新版本，跳过下载${NC}"
            return 1
        else
            echo -e "${YELLOW}发现新版本：${LATEST_VER}（当前：v${LOCAL_VER}）"
            read -p "是否更新？(Y/n): " update_confirm
            [[ $update_confirm =~ [nN] ]] && return 1
        fi
    fi

    echo -e "${BLUE}开始下载：${DOWNLOAD_URL}..."
    if ! curl -LO --progress-bar "$DOWNLOAD_URL"; then
        fatal_error "下载失败，错误代码：$?"
    fi
    return 0
}

# 生成客户端配置
generate_client_config() {
    echo -e "\n${GREEN}=== 客户端配置生成向导 ===${NC}"
    
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
    
    DEFAULT_SAVE_PATH="${CONFIG_DIR}/client/${CLIENT_NAME}.ini"
    read -p "请输入保存路径（默认 ${DEFAULT_SAVE_PATH}）: " SAVE_PATH
    SAVE_PATH=${SAVE_PATH:-$DEFAULT_SAVE_PATH}
    mkdir -p $(dirname "$SAVE_PATH")
    
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
detect_system
install_dependencies

# 选择访问方式
echo -e "${BLUE}[3/15] 选择访问方式..."
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
generate_cert

# 端口配置
echo -e "${BLUE}[5/15] 端口配置..."
configure_port "TCP绑定端口" 31943 tcp BIND_PORT
configure_port "KCP绑定端口" $BIND_PORT udp KCP_PORT
configure_port "QUIC绑定端口" 31944 udp QUIC_PORT
configure_port "Dashboard端口" 7500 tcp DASH_PORT

# 配置防火墙
configure_firewall

# 下载流程
echo -e "${BLUE}[6/15] 开始下载流程..."
if smart_download; then
    echo -e "${GREEN}✅ 下载完成，开始解压..."
    tar zxf "${FRP_PACKAGE}" || fatal_error "解压失败"
    cd "frp_${LATEST_VER//v}_linux_${ARCH}" || fatal_error "进入目录失败"
else
    echo -e "${YELLOW}⚠️ 跳过下载流程..."
    FRP_DIR=$(find / -path "*frp_*_linux_${ARCH}" -type d 2>/dev/null | head -1)
    [ -z "$FRP_DIR" ] && fatal_error "找不到现有安装文件"
    cd "$FRP_DIR" || fatal_error "进入本地安装目录失败"
fi

# 安装配置
echo -e "${BLUE}[7/15] 生成配置文件..."
mkdir -p "${CONFIG_DIR}/client"
cat > "${CONFIG_DIR}/frps.toml" <<EOF
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
enable_prometheus = true

transport.tls.enable = true
transport.tls.certFile = "${CERTS_DIR}/fullchain.pem"
transport.tls.keyFile = "${CERTS_DIR}/privkey.pem"

log_file = "/var/log/frp/frps.log"
log_level = "info"
log_max_days = 14
EOF

# 安装服务
echo -e "${BLUE}[8/15] 安装系统服务..."
install -m 755 frps /usr/local/bin/ || fatal_error "可执行文件安装失败"

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

# 生成凭证
echo -e "${BLUE}[9/15] 生成安全凭证..."
FRP_TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
DASH_USER="admin"
DASH_PWD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 16 | head -n 1)

# 存储凭证
mkdir -p "${CONFIG_DIR}/env"
echo "${FRP_TOKEN}" > "${CONFIG_DIR}/env/frp_token"
echo "${DASH_PWD}" > "${CONFIG_DIR}/env/dashboard_pwd"
chmod 600 "${CONFIG_DIR}/env"/*

# 启动服务
echo -e "${BLUE}[10/15] 启动FRP服务..."
systemctl daemon-reload
systemctl enable frps
systemctl restart frps || fatal_error "服务启动失败"

# 验证安装
echo -e "${BLUE}[11/15] 验证安装..."
sleep 3
if ! systemctl is-active --quiet frps; then
    fatal_error "服务未正常运行"
fi

HTTP_CODE=$(curl -sko /dev/null -w "%{http_code}" "https://${DOMAIN}:${DASH_PORT}")
if [ "$HTTP_CODE" != "200" ]; then
    echo -e "${YELLOW}⚠️ Dashboard访问异常，HTTP状态码: ${HTTP_CODE}"
    echo -e "请检查："
    echo -e "1. 防火墙设置"
    echo -e "2. 证书有效性"
    echo -e "3. 服务日志：journalctl -u frps${NC}"
fi

# 显示安装结果
echo -e "\n${GREEN}
########################################
#          安装成功！重要信息         #
########################################
${NC}"

echo -e "${YELLOW}▸ 服务端地址：${GREEN}${SERVER_ADDR}${NC}"
echo -e "${YELLOW}▸ 系统架构：${GREEN}${ARCH}${NC}"
echo -e "${YELLOW}▸ 操作系统：${GREEN}${OS_TYPE}${NC}"
echo -e "${YELLOW}▸ 主要端口："
echo -e "  - TCP: ${BIND_PORT} (主服务)"
echo -e "  - KCP: ${KCP_PORT} (加速)"
echo -e "  - QUIC: ${QUIC_PORT} (协议)"
echo -e "  - Dashboard: ${DASH_PORT} (监控)"
echo -e "${YELLOW}▸ Dashboard访问地址：${GREEN}https://${DOMAIN}:${DASH_PORT}${NC}"
echo -e "${YELLOW}▸ Prometheus监控端点：${GREEN}https://${DOMAIN}:${DASH_PORT}/metrics${NC}"
echo -e "${YELLOW}▸ 登录凭证："
echo -e "  用户名：${GREEN}${DASH_USER}${NC}"
echo -e "  密码：${GREEN}${DASH_PWD}${NC}"
echo -e "${YELLOW}▸ FRP Token：${GREEN}${FRP_TOKEN}${NC}"
echo -e "${YELLOW}▸ 配置文件路径：${GREEN}${CONFIG_DIR}/frps.toml${NC}"
echo -e "${YELLOW}▸ 安装日志：${GREEN}${LOG_FILE}${NC}"

# 生成客户端配置
read -p "是否生成客户端配置文件？(Y/n): " gen_client
[[ $gen_client =~ [nN] ]] || generate_client_config

echo -e "\n${GREEN}提示："
echo -e "1. 客户端需使用相同Token连接"
echo -e "2. 监控数据可通过Prometheus采集"
echo -e "3. 查看实时日志：journalctl -f -u frps${NC}"
