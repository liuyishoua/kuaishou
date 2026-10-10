<div align="center">
  <p align="center">
    <a href="https://github.com/cv-cat/KuaiShou-Spider" target="_blank" rel="noopener" alt="KuaiShou-Spider">
      <img width="220" src="./assets/logo.svg" alt="KuaiShou-Spider logo">
    </a>
  </p>

  <div align="center">
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/nodejs-18%2B-green" alt="Node.js 18+"></a>
    <a href="https://github.com/cv-cat/KuaiShou-Spider/stargazers"><img src="https://img.shields.io/github/stars/cv-cat/KuaiShou-Spider?style=flat" alt="GitHub stars"></a>
    <a href="https://github.com/cv-cat/KuaiShou-Spider/network/members"><img src="https://img.shields.io/github/forks/cv-cat/KuaiShou-Spider?style=flat" alt="GitHub forks"></a>
    <a href="https://github.com/cv-cat/KuaiShou-Spider/commits/master"><img src="https://img.shields.io/github/last-commit/cv-cat/KuaiShou-Spider" alt="Last commit"></a>
  </div>

  # 🎵 KuaiShou-Spider

</div>

**✨ 面向快手 Web 的数据采集、直播监听与创作者发布工具。**

项目把快手网页端的登录、数据请求、直播 WebSocket 和创作者中心流程整理成一个可复用的 Python 客户端。运行时不启动 Chrome、不读取浏览器用户目录，登录态和临时票据只保存在当前进程或用户自己的本地配置中。

> ⚠️ 本项目仅供学习、测试和技术研究使用。请遵守快手平台规则与当地法律，只对自己有权操作的账号、直播间和素材使用；不要用于骚扰、批量刷量、绕过风控或发布违法违规内容。

## 🌟 功能特性

- ✅ **数据采集**：作品详情、短视频信息、用户主页、作品列表、搜索、评论和分页
- 🎙️ **直播间监听**：房间发现、房间状态、主播信息，以及 WebSocket 实时弹幕、礼物、点赞和系统通知
- 🚀 **创作者发布**：视频上传审核发布、多图图集上传审核发布（1～31 张），支持扫码 / 手机号 / Cookie 登录快速验证
- 🔐 **统一认证**：二维码登录、手机号验证码登录和用户 CK 登录；www、Live、CP 会话按站点隔离刷新
- 🧰 **便捷输出**：支持结构化 JSON、Excel 和媒体下载，便于接入定时任务或 AI Agent

## 🎨 项目预览

<img width="1609" height="460" alt="image" src="https://github.com/user-attachments/assets/f57df582-34e0-40c7-a034-c526ac1ff832" />


### 快速验证

编辑根目录 `quick_publish.py` 顶部配置后运行：

```bash
python quick_publish.py
```

支持三种登录方式：

- `LOGIN_MODE = "qr"`：扫码登录
- `LOGIN_MODE = "phone"`：手机号 + 短信验证码
- `LOGIN_MODE = "cookie"`：填写本地 `COOKIES` 或环境变量 `KS_COOKIES`

发布示例默认使用“仅自己可见”。上传和发布会产生真实外部副作用，请先确认账号、素材和可见性设置。

图文可以在 `MEDIA_PATHS` 中按顺序填写 1～31 张图片；底层会逐张执行
`upload/pre → 分片上传 → upload/single/finish`，全部完成后再执行一次
`upload/finish → publish/submit`。JPG、JPEG、WEBP、BMP、GIF、TIFF 等常见格式会
在进程临时目录转换为 PNG，原文件不会被修改。视频发布时仍只填写一个视频路径。

## 🛠️ 快速开始

### ⛳ 运行环境

- Python 3.10+
- Node.js 18+
- Windows、Linux 或 macOS

### 🎯 安装依赖

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

Node.js 只用于执行仓库内必要的 webweapon / 令牌桥接脚本，不需要启动浏览器，也不需要把浏览器 Cookie 导入程序。

### 🎨 配置登录

复制 `.env.example` 为 `.env`，只在本地填写自己的完整 Cookie：

```dotenv
KS_COOKIES='did=...; userId=...; ...'
```

不填写 Cookie 时，业务代码可以使用二维码登录；手机号登录则在程序申请短信后，将自己收到的验证码输入终端。Cookie、手机号、短信验证码和登录票据都不要提交到 GitHub。

### 🚀 运行数据采集

```bash
python main.py
```

`main.py` 是最小数据采集入口，可按需要修改为作品详情、搜索、用户页或媒体下载任务。

### 🎙️ 监听直播间

业务代码创建 `LiveDanmakuClient` 后即可监听直播间实时消息。客户端会自动完成 Live 站点会话检查、房间发现、WebSocket 握手、心跳和有限次重连。

当前版本已验证“接收”弹幕、礼物和点赞；直播间主动发送弹幕尚未接入。

## 🗝️ 注意事项

- 登录态具有时效性，失效后请重新输入 CK 或重新登录。
- 推荐流接口可能随线上版本返回 400；遇到合同变化时请重新取证，不要猜字段或重放旧登录态。
- 图文发布支持 1～31 张图片；底层按浏览器真实顺序逐张申请和上传，常见非 PNG 图片会临时转换为 PNG 后上传。当前上传合同要求单张图片不超过 4MB；视频是否被服务端接受取决于素材容器和账号权限。
- 直播监听依赖房间当前在播、Live 票据、WebSocket token 以及账号 / IP 风控状态。
- `.env`、二维码、`reverse/secrets`、浏览器 Cookie、原始抓包、测试素材和运行输出均不应上传。

## 🍥 更新日志

| 日期 | 说明 |
| :--: | :-- |
| 2026-08-30 | 图文发布支持 1～31 张图片，补齐逐图上传、图集收尾和快速验证配置。 |
| 2026-08-30 | 重写 GitHub README，补充 Logo、Star History、交流群和公开发布说明。 |
| 2026-08-30 | 对齐 Live 首页 / 房间 Cookie 合同，补齐直播票据刷新和 WebSocket 重连流程。 |
| 2026-08-29 | 整理独立 `feat/kuaishou` 运行分支，加入根目录快速发布示例，移除旧测试和中间产物。 |
| 2026-08-28 | 完成 Live WebSocket protobuf 解码、弹幕 / 礼物 / 点赞监听。 |
| 2026-08-27 | 完成二维码、手机号、Cookie 登录，设备指纹、webweapon、TLS/HTTP 和 CP 发布链路。 |

## 🤝 欢迎贡献 PR

欢迎提交文档改进、兼容性修复和新的脱敏请求合同：

- Fork 本仓库并在新分支上开发
- PR 中说明改动目的、验证范围和可能的外部副作用
- 不要提交账号 Cookie、二维码、会话状态、原始抓包或测试素材
- 也欢迎通过 [Issue](https://github.com/cv-cat/KuaiShou-Spider/issues) 反馈问题

## 📈 Star 趋势

<a href="https://cvcat.site/star-history/svg?repos=cv-cat/KuaiShou-Spider&type=Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cvcat.site/star-history/svg?repos=cv-cat/KuaiShou-Spider&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://cvcat.site/star-history/svg?repos=cv-cat/KuaiShou-Spider&type=Date" />
    <img alt="Star History Chart" src="https://cvcat.site/star-history/svg?repos=cv-cat/KuaiShou-Spider&type=Date" />
  </picture>
</a>



## 🍔 交流群

如果你对爬虫和 AI Agent 感兴趣，可以加入群聊一起讨论~

ps: 请加群，人满或者过期 issue | wx 提醒 | qq提醒

| group-1 | group-2 | group-3 | group-4 (2000人qq群) |
|:--:|:--:|:--:|:--:|
| <img width="280" alt="group1" src="https://cvcat.site/assets/group1.jpg" /> | <img width="280" alt="group2" src="https://cvcat.site/assets/group2.jpg" /> | <img width="280" alt="group3" src="https://cvcat.site/assets/group3.jpg" /> | <img width="280" alt="group3" src="https://cvcat.site/assets/group4.jpg" /> |
