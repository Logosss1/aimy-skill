# aimy-skill 项目工作规范

## 项目定位
轻量级渗透测试辅助工具链（AI Agent Ready）。定位是**验证判定层**：
发现可疑点后快速确认、取证据、出报告，而不是全站盲扫。

## 目录结构
- `main.py` — CLI 入口（`aimy = "main:main"`）
- `cli/` — 参数解析与命令注册（`arg_parsers.py` / `check_commands.py`）
- `tools/` — 检测与利用模块（SQLi / XSS / SSRF / IDOR / 反序列化 / 提权 / 横向移动等）
- `engine/` — 判定引擎（`config` / `cvss` / `diff` / `layering` / `oob` / `reproducibility`）
- `payload_seeds/` — 分数据库的 payload 种子（mysql / mssql / oracle / postgresql / ...）
- `data/` — 指纹与 CMS 漏洞库
- `docs/` — 实战手册（`src_hunting` / `vuln_playbooks` / `tool_guide` / `report_writing`）
- `ai-mian/hack-skills/skills/` — 漏洞打法技能库（每个目录一个 `SKILL.md`）
- `tests/` — pytest 测试集

## 常用命令
### 信息收集
    recon / portscan / dirfuzz / crawl / param-mine / waf
### 登录保活
    login --auth-url URL --auth-type form --auth-user U --auth-pass P --session-file sess.json
### 定向检测
    sqlcheck / sqli-weaponize / xsscheck / xss-validate / cmdi / ssti / lfi / idor / smuggler / graphql
### 编排
    python main.py auto-pwn --target URL --session-file sess.json

命令全量参考见 `docs/tool_guide.md`。

## 开发约定
- Python >= 3.8，依赖见 `pyproject.toml` / `requirements.txt`
- 代码风格：ruff，`line-length = 100`，`target-version = py38`
- 测试：pytest，`testpaths = ["tests"]`，默认带覆盖率统计

      pytest tests/ -q
      pytest tests/test_orchestrator.py -x -q --no-cov

- 静态检查：`ruff check .` / `mypy tools/` / `bandit -r tools/`
- 新增检测模块后，同步在 `cli/check_commands.py` 注册命令，并补对应 `tests/`

## 平台注意事项
- 本地 Kali 工具在 Windows 上经 WSL 调用，路径统一使用正斜杠
- 本地命令执行逻辑在 `tools/kali_executor.py`：无 shell 特性的简单命令走
  `shlex.split` 列表执行；含管道/重定向的命令走 `shell=True`
- 输出统一走 `tools/output.py` 的 `output()`，保证 JSON 结构一致
- 跨模块情报共享用 `tools/context_memory.py`（线程安全）

## 相关文档
- 架构审计：`docs/ARCHITECTURE_AUDIT.md`
- 项目地图：`docs/PROJECT_MAP.md`
- 重构计划：`docs/REFACTOR_PLAN.md`