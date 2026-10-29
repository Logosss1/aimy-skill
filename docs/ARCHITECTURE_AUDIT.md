# aimy-skill 架构审计（v3.7.5）

> 本文档已按当前实现更新。历史版本中的 pickle session、`../payload_seeds`
> 相对路径、orchestrator 全部逻辑单文件等结论已不再成立。

## 1. 入口与数据流

```
main.main()
  ├── cli.arg_parsers.build_parser()      88 个顶层命令（含 manifest）
  ├── cli.check_commands.build_dispatcher() 56 个数据驱动 check 命令
  ├── tools.output.configure(--json/--quiet)
  └── args.func(args)
        ├── Orchestrator.run()            9 个 phase，ThreadPool 并行
        ├── 单点 check 命令                直接调用 detector.check()
        └── _output(report)               stdout JSON
```

## 2. 关键组件

| 组件 | 位置 | 说明 |
|---|---|---|
| 懒加载公共出口 | `tools/__init__.py` | PEP 562 `__getattr__`，避免 CLI 启动加载 45 个模块 |
| 编排器 | `tools/orchestrator.py` | 仍较大（约 2200 行，ruff 格式化后行数增加）；报告阶段已拆到 `orchestrator_engine/report_phase.py`（155 行） |
| 检测分发 | `tools/orchestrator_engine/helpers.py` | `inspect.signature.bind` 预绑定；签名不匹配才回退位置参数 |
| 判定引擎 | `engine/` | 差分、证据分层、OOB 判定、复现性、CVSS、契约告警 |
| 上下文记忆 | `tools/context_memory.py` | 单例 + RLock；`begin_run(target)` 防止顺序多目标串数据 |
| 资源读取 | `tools/resources.py` | `importlib.resources`，兼容源码与 wheel |
| 输出 | `tools/output.py` | `output()` stdout / `progress()` stderr / `error()` 结构化错误 |
| 字典生成 | `tools/wordgen.py` + `wordlists/` | 内置弱口令字典、leet/年份/后缀变换、合并去重；john/hashcat 规则随包 |
| 报告 | `tools/reporter.py` | JSON / HTML / SARIF 2.1.0 / Markdown |
| 会话持久化 | `tools/auth_engine.py` | JSON 文件，写入后 `chmod 0600` |

## 3. 已修复的关键问题

- **wheel 资源缺失**：`payload_seeds/`、`data/` 改为资源包 + package-data；PyYAML 进入运行时依赖。
- **测试依赖真实网络**：`SecondOrderVerifier` 默认改为 `requests.Session`；`oast.fun` 改为
  `AIMY_OOB_DOMAIN` 显式开启；契约测试注入 fake session；`conftest.py` 让 localhost 绕过系统代理。
- **CI 门禁缺口**：全仓库 ruff + format + mypy + bandit(High) + 覆盖率 80% + wheel 安装 smoke。
- **AI 输出不纯**：`orchestrator` 的 126 条 `print` 改为 `progress(stderr)`；新增 `--json` / `--quiet`。
- **HTML 报告时间 bug**：`datetime.fromtimestamp(str)` 导致 `save_report` 静默失败，现已兼容 ISO 字符串。
- **安全默认值**：OOB 回调增加随机 token 与 404 拒绝；session 文件 0600；
  XML 解析改用 defusedxml；移除 `eval`；MD5 标注 `usedforsecurity=False`。

## 4. 仍存在的风险

1. `orchestrator.py` 体量仍大（约 2200 行），phase 之间共享状态多；报告阶段已拆为 mixin，
   其余 phase 建议继续按同样方式拆分（注意测试里对 `tools.orchestrator.*` 全局的 patch 需要同步迁移）。
2. `context_memory` 仍是进程级单例；同进程**并发**扫描不同目标仍可能交叉污染。
3. 检测器返回结构不统一；`tools/output.py` 已在输出边界统一过 `CheckResult`，
   但 detector 之间仍在内部返回自由 dict，建议后续在 dispatcher 层也做同样归一化。
4. 检测器签名仍不完全统一；分发层已用 `signature.bind` 预检，但旧式位置参数 detector 仍需兼容。
5. `kali_executor._run_local` 的 `shell=True` 与 `paramiko.exec_command` 属于工具固有能力，
   需要保证命令构造只来自受信输入。
6. `tool_registry` 仅 33 个工具，`list` 与 88 个 CLI 命令口径不一致；`manifest` 是 Agent 的权威目录。
7. 部分 `except Exception: pass` 仍是静默失败（约 146 处直接 pass）；建议逐步改为 debug 日志。

## 5. 测试与基准

- `tests/`：2844 个用例，默认离线；联网用例标记 `online`，需 `--run-online`。
- `bench/`：DVWA + 内置 lab 靶场；新增 `--case-timeout` 硬超时与逐用例 flush 进度。
- 覆盖率门槛：80%（`pyproject.toml`）。
