# 快手工作台

浏览器入口： https://portal.example.com:20040/ 。从 https://portal.example.com/ 门户点击 `kuaishou` 也可进入。

五个新增工作台使用用户指定的统一访问密码，保存在各自 `.local/web/admin-password` 中（不写入源码或文档）。工作台登录与平台登录独立；进入后打开「账号连接」完成平台认证。新工作台没有预置平台账号。

## 已接入能力

- 作品搜索与游标翻页
- 作品详情与评论
- 用户作品与账号内容列表
- 直播间状态查询
- 收藏、标签与 CSV / JSON 导出
- 扫码 / Cookie 登录与会话保存

## 专项工具

- 直播间状态
- 我的点赞
- 我的收藏
- 浏览历史

## 操作流程

1. 在「账号连接」导入本人的登录 Cookie，或使用 App 扫码确认。
2. 在「内容发现」或「专项工具」主动发起查询。任务在后台执行，状态、失败与结果不确定会分别记录。
3. 结果点击「收藏」进入资料库；可编辑标签、备注、筛选并导出 CSV / JSON；支持整批收藏且保留原有标签、备注。数据按平台账号 ID 隔离，断开连接不删除本地资料。
4. 「创作草稿」保存本地正文。当前工作台不向平台发布，官方网页负责创作提交。

## 架构与运行

沿用闲鱼工作台的 Flask + Waitress、`app.py / service.py / platform.py` 分层。保留上游独立仓库和 SDK；没有迁入 Bifrost。

- `web/app.py`：工作台登录、同源保护与固定路由。
- `web/service.py`：SQLite 资料、账号隔离、后台任务与去重。
- `web/platform.py`：真实平台适配，响应归一化、链接校验、请求上限。
- `web/config.py`：页面能力与专项工具清单。
- `web/demo.py`：离线夹具，禁止真实登录和发布。
- `.local/web/`：访问密码、平台凭据、会话与数据库，目录私有且 Git 忽略。

本机接口 `http://127.0.0.1:20008`，正式服务 `kuaishou-web.service` 与 `kuaishou-proxy.service`。

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-web.txt
.venv/bin/python -m web --port 20008 --public-origin https://portal.example.com:20040
```

离线验收：

```sh
.venv/bin/python -m unittest discover -s web/tests -v
node --check web/static/app.js
.venv/bin/python -m web --demo --no-auth --port 20025 --data-dir /tmp/kuaishou-preview
```

`--no-auth` 仅允许回环地址且不接受公网 Origin。正式服务不用演示数据。

## HTTP 接口

- `GET /api/meta`：当前账号、运行模式、能力与工具清单（不含凭据）。
- `GET /api/overview`、`/api/library`、`/api/drafts`、`/api/jobs`、`/api/jobs/<id>`。
- `POST /api/searches`：`keyword, order, page, request_id`；返回任务，结果见 `/api/jobs/<id>`。
- `POST /api/details`：`value, request_id`。
- `POST /api/comments`：`id, request_id`，目标必须来自本账号查询结果。
- `POST /api/users`：`uid, page, request_id`；仅内容平台支持。
- `POST /api/tools/<name>`：配置中列出的固定工具及相应表单参数，未知工具拒绝。
- `POST /api/library/<id>` 收藏已有查询结果；`PATCH` 更新 `tags, note`；`DELETE` 移出收藏。
- `GET /api/export`：当前账号资料库 JSON；`?format=csv` 导出可供表格软件打开的 CSV。
- `POST /api/library/batch`：`ids` 批量收藏本账号查询结果，最多 1000 条，保留已有标签、备注。
- `POST /api/drafts`：`title, text` 新建，带 `id` 编辑；保存不发布。
- `POST /api/drafts/<id>/publish`：仅 B站、微博启用，参数 `confirm:true, request_id`。
- `POST /api/account/import`：`cookie`；`/check`、`/disconnect` 管理连接；支持平台另提供 `/qr`、`/qr/<token>`。

写请求需要匹配公网 Origin、`X-App-Request: 1` 与 JSON。所有 API 需要独立工作台会话。上游示例不要用于验收。

## 上游与验证边界

上游：https://github.com/cv-cat/KuaiShou-Spider ，接入版本 `3ef36e335f87a31fe453bc6e0572435c0034902f`。真实接口会受平台登录、账号权限、限流和接口变更影响。演示验收与真实账号业务成功必须分别报告。

页面与离线流程完成验证后，不代表私人订单、登录后评论、真实发布已实测。当前没有五个平台的用户登录态；正式页面会明确显示「账号未连接」。发布验收只用本地适配器，不向平台发送测试内容。


## 标签页面保留

切回已打开标签时复用当前窗口中的页面和事件，保留工具参数、筛选、查询结果及未保存草稿；公共侧栏不重复创建。写入或显式刷新会清理无未保存内容的旧缓存，平台账号变化清空全部缓存。缓存不写入浏览器存储。跨工作台约定与隔离浏览器验证见 `../../agent-tools/docs/workspace-tab-cache.md`。
