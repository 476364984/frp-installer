# FRP 服务端一键安装器

[![GitHub release](https://img.shields.io/github/v/release/476364984/frp-installer)](https://github.com/476364984/frp-installer)

## 功能特性
- 全自动部署 FRP 服务端
- 支持多架构 (x86_64/ARM64/ARMv7)
- 自动配置 TLS 加密
- 交互式参数设置
- 防火墙自动适配（支持 firewalld/ufw）

## 系统要求
- Linux 系统（CentOS 7+/Ubuntu 18.04+/Debian 10+）
- 需要 root 权限

## 使用指南
### 快速开始
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/476364984/frp-installer/main/install_frps.sh)"
