# 工作台开发约定

- 工作台位于 `web/`，入口 `.venv/bin/python -m web`。HTTP 在 `app.py`，本地数据与任务在 `service.py`，真实适配在 `platform.py`，能力清单在 `config.py`。
- 使用 `web/demo.py` 与临时目录验证；演示模式禁止真实登录与发布。不要运行上游示例入口，它们可能输出登录态或执行真实操作。
- `.local/` 保存账号 Cookie、会话、密码和数据库，不提交、不输出。公开部署必须保留登录、同源检查和独立 Cookie 名。
- 数据按平台用户 ID 隔离。保存草稿、收藏、备注不写入平台；发布必须显式确认，保留去重和不确定结果不自动重试的语义。
- 检查：`.venv/bin/python -m unittest discover -s web/tests -v`；前端修改运行 `node --check web/static/app.js`，并使用现有 Playwright 对临时演示实例检查交互。
- 部署沿用 `kuaishou-web.service` 与 `kuaishou-proxy.service`。门户只修改 Bifrost 链接目录，不修改其他应用。
- 实际页面、账号认证、平台数据请求、真实发布的验证状态分别说明；不要将演示数据或排队结果称为平台成功。

- Agent 目录：`/api/channel/catalog` 通过服务端实时访问 Multica；单选绑定经 `/v1/bindings` 固定当前来源/账号/用途，不以已有路由限制目录。`channel-task` 保留首次执行身份，改名/换绑不重写历史。目录故障明确失败，无旧列表回退。新增回归位于 `web/tests/test_channel_agents.py`。
