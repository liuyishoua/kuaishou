# kuaishou

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-orange)](LICENSE)

独立运行的快手工作台，基于 [cv-cat/KuaiShou-Spider](https://github.com/cv-cat/KuaiShou-Spider) 增加 Web 控制台。
包含作品搜索、详情与评论、创作者作品、直播状态、点赞收藏与浏览历史、本地资料库和研究笔记。
Python 后端、原生 HTML/JS 前端、SQLite 数据库，无需 Bifrost 或前端编译。

## 界面预览

以下为本项目离线演示模式截图，账号和内容均为模拟数据。

![快手工作台演示](docs/images/overview.png)

## 一键启动

先安装 **Python 3.10+**，克隆仓库后运行：

```bash
git clone https://github.com/liuyishoua/kuaishou.git
cd kuaishou
python3 start.py
```

Windows 可双击 `start.bat`；macOS 可双击 `start.command`；Linux 可运行 `./start.sh`。
首次启动自动创建 `.venv`、安装 Python 依赖，成功后尝试打开 **http://127.0.0.1:8776**。
首次安装需要联网，后续依赖不变时直接启动。按 Ctrl+C 停止。

默认是**演示模式**，使用独立模拟账号和内容，不联系真实平台。
工作台访问密码保存在 `.local/web-demo/admin-password`；工作台登录与平台账号连接分别管理。

```bash
# 更换端口或在服务器上运行
python3 start.py --port 8876 --no-browser
```

## 真实账号模式

安装 **Node.js 20+**（平台签名辅助代码需要时使用），然后运行：

```bash
python3 start.py --real
```

支持 App 扫码或 Cookie 连接。工作台不向平台发布作品，草稿保存在本地。
首次运行的访问密码保存在 `.local/web/admin-password`，进入后连接自己的平台账号。
真实能力受登录状态、账号权限和平台接口返回影响；演示运行成功不代表真实平台业务已经联调。
模型起草与分析由可选 Channel 接入提供，普通查询无需部署 Channel。

## 数据与备份

- 演示数据：`.local/web-demo/`；真实工作台数据：`.local/web/`。
- 账号会话、Cookie、访问密码、数据库和上传素材只保存在本地。
- 收藏、标签、备注和草稿按平台账号隔离，保存草稿不会自动发布。
- 真实写入使用请求 ID 去重；结果不确定时不自动重试。
- 备份前停止服务，复制整个 `.local/`；数据、`.env`、密钥和虚拟环境不提交 Git。

## 手动安装与验证

```bash
python3 -m venv .venv
# Linux / macOS；Windows 使用 .venv\Scripts\python.exe
.venv/bin/python -m pip install -r requirements-web.txt
.venv/bin/python -m web --demo
.venv/bin/python -m unittest discover -s web/tests -v
node --check web/static/app.js
```

真实模式如存在根目录 `package.json`，还需安装 Node.js 依赖；一键启动会在依赖目录缺失时执行 `npm install`。
不要运行上游示例脚本作为工作台入口，它们可能输出登录态或执行真实平台操作。

## 目录

- `web/`：HTTP 服务、业务逻辑、平台适配、前端和回归测试。
- `docs/workspace.md`：功能范围、接口与部署说明。
- `deploy/`：systemd 和 HTTPS 反向代理示例，部署时调整域名及本机路径。
- `start.py`、`start.sh`、`start.command`、`start.bat`：一键启动入口。
- 其余平台接口、签名资源及原始例程保留原有来源标注。

原项目说明保存在 [docs/upstream-readme.md](docs/upstream-readme.md)。

## 使用许可

**本项目仅供学习、研究、测试及其他非商业用途，不得用于商业目的。**
对本仓库中版权所有者拥有权利的代码，采用
[PolyForm Noncommercial License 1.0.0](LICENSE)；商业使用须事先取得版权所有者的单独授权。
本项目属于**源码可见、限制商用**，不应标为 MIT 或 OSI 意义上的开源许可证。

第三方代码、素材和依赖仍受其各自许可条件约束，来源与许可范围见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。本声明不追溯改变第三方代码或此前已发布版本的许可。


### 持续运营与应用中心

工作台侧栏的「持续运营与待办」打开 `/operations`。计划按连接账号隔离，创建后暂停；手动启动后由服务端每 10 秒检查到期计划，关闭网页不影响执行。执行间隔最少 5 分钟。搜索读取当前页，评论读取当前页（知乎前两页），结果按计划和源条目去重，最多保留 2000 条，界面展示最近 100 条。覆盖范围不是完整历史。平台读取失败会暂停为「需要处理」，检查账号与目标后可恢复。

新增结果可收藏、标记处理、交给实时 Multica Agent 目录中的 Agent 分析。模型仅生成分析建议，不自动发布。B站支持将目标视频／评论保存为评论草稿，核对账号、目标和正文后提交；平台接受与可见性核验分开，未知结果保持待核对且不重发。其他工作台尚未接入评论发送与私信接口，页面明确标示；已有抖音、闲鱼、小红书监听保持独立。

应用中心位于 `https://d.58nft.net:9461/platform-select`，链接在新标签页打开。生产入口使用统一运营身份，平台子账号凭证按运营用户隔离。离线验收使用临时 `--demo --no-auth --data-dir`，不要在真实账号启动计划进行测试。


### 统一运营身份与数据归属

生产应用中心为 `https://d.58nft.net:9461/platform-select`。登录后点击工作台无需再次输入工作台密码；第三方平台子账号仍需完成对应平台授权。工作台显示当前运营用户，统一退出会撤销该用户的统一登录会话。

启用条件是数据目录内存在私有 `workspace-owner.json`，包含 `owner_id`、`owner_username` 与 `public_origin`。现有数据明确归属 Leo（用户 ID 1）；其他运营用户的数据创建在 `users/<已验证用户ID>/`，其子账号、平台登录态、任务及业务数据独立。用户身份由独立 `ops-hub` 服务（127.0.0.1:8787）逐请求验证，客户端传入的用户 ID 不参与归属判定；验证服务故障时拒绝访问。新用户不会继承 Leo 的模型、Channel 或平台凭证。

内部调用使用数据目录中的私有 `workspace-machine-key`，通过 `X-Ops-Machine-Key` 传递，明确对应原数据所有者；配置文件与密钥不得提交或输出。删除所有者配置会恢复旧模式，仅应在受控维护中进行。演示模式不启用统一身份，可使用隔离临时数据测试。Channel、总部和账号中心当前仅向已分配的原所有者开放，其他用户不会自动获得这些资源。
