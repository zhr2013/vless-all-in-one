# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.2] - 2026-01-28

### Added
- 新增用户级路由配置功能
  - 同端口不同用户可配置不同出站路由（直连/WARP/链式代理/负载均衡）
  - 用户级路由优先于全局分流规则
  - 添加用户时可选择专属路由
  - 用户管理菜单新增「修改用户路由 (r)」选项
  - 用户列表显示路由配置列
- 新增 XHTTP TLS+CDN 模式
  - 安装 VLESS-XHTTP 时可选择 Reality 模式或 TLS+CDN 模式
  - TLS+CDN 模式使用真实证书，支持通过 Cloudflare CDN（小云朵）代理
  - 自动配置 Nginx 反代 XHTTP (gRPC/h2c) 协议
  - 适合 IP 被墙场景，CDN 保护入站连接
- 新增 VLESS-WS 无 TLS 模式（VLESS-WS-CF）
  - 专为 Cloudflare Tunnel 场景设计
  - 服务器端不需要 TLS，由 CF Tunnel 提供加密
  - Cloudflare Tunnel 快速隧道/命名隧道支持检测
  - 隧道状态页面显示分享链接和二维码

### Fixed
- 修复端口输入循环无法退出的问题（添加 0/q 退出选项）
- 修复 alpine 系统无法查询流量统计问题
- 修复 tgbot 循环发送消息问题 
- 修复 Xray 日志目录不存在导致服务启动失败的问题

## [3.4.1] - 2026-01-27

### Added
- 新增多IP入出站配置功能
  - 支持多IP服务器按入站IP路由到指定出站IP
  - 自动检测系统所有公网IPv4/IPv6地址
  - 交互式管理菜单（添加/删除/启用/禁用规则）
  - 自动生成Xray outbound和routing配置
  - 入口位于：分流配置 → 多IP入出站配置

### Changed
- 优化分流管理菜单布局

## [3.4.0] - 2026-01-26

### Added
- 新增多用户管理功能
  - 添加/删除/查看用户
  - 用户流量配额与统计
  - 实时流量监控
  - 用户启用/禁用
  - 用户分享链接查看
  - TG 通知配置
- 新增 Cloudflare Tunnel 内网穿透功能
  - 支持快速隧道（临时域名）和命名隧道（自定义域名）
  - 适用于 NAT 机器或动态 IP 环境
- 新增双层链式代理 (WARP → 落地节点)
  - 隐藏真实 IP + 解锁流媒体
- 新增随机 SNI 伪装功能
  - 自动随机选择主流网站 SNI
- 新增负载均衡组管理
  - 支持 leastPing/random/roundRobin 策略

### Fixed
- 修复 Alpine 系统 Nginx 安装和配置问题

### Changed
- 优化用户添加/删除后自动重载配置
- 改进菜单布局和交互体验

## [3.3.0] - 2026-01-18

### Added
- 新增 SOCKS5 无认证模式支持
- 新增多端口实例功能与首页显示优化

### Fixed
- 修复 SOCKS5 配置显示中的乱码问题
- 修复全新机器安装 SOCKS5 失败的问题
- 修复数据库函数 JSON 格式问题
- 修复 SOCKS5 和 VMess-WS 协议的 Xray 安装调用
- 移除 SOCKS5 配置中的错误 ip 字段

### Changed
- SOCKS5 无认证模式根据双栈支持智能选择默认监听地址

## [3.2.2] - 2026-01-16

### Added
- 新增 SOCKS5 服务器自定义用户名和密码支持
- 新增一键导入 Alice 家宽功能
  - 支持 Alice 节点负载均衡组管理
  - 支持 SOCKS5 负载均衡器使用 leastPing 策略
  - 集成负载均衡配置到导入流程
  - 分流规则选择出口时支持跳过延迟检测
- 新增 sing-box 负载均衡支持

### Fixed
- 修复完全卸载时未清理 Caddy 二进制文件的问题
- 修复 Alice 节点负载均衡器 SOCKS5 协议兼容性问题
- 删除重复的负载均衡函数定义
- 增强 URL 构建变量替换兼容性
- 增强卸载流程,支持清理所有版本的 Caddy (包括 NaïveProxy 自定义编译版本)

### Changed
- 重构节点延迟检测机制并优化批量测速性能
- 优化出口加载性能,减少 jq 调用次数
- 移除危险操作确认机制并优化解析逻辑

## [3.2.1] - 2026-01-15

### Changed
- 更新版本号至 v3.2.1

## [3.2.0] - 2025-XX-XX

### Added
- 完善核心版本管理与缓存
- 新增核心更新管理功能

### Fixed
- 修复 Snell v4 版本配置兼容性问题
- 优化 IPv6 双栈监听策略与系统兼容性
- 添加 ACME 账户邮箱验证功能
- 更新 acme.sh 安装邮箱配置

### Changed
- 优化分流规则菜单布局，按字母倒序排列
- 在分流规则菜单中添加新规则选项
