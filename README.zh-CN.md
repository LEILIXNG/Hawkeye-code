<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

一款面向 Java/Spring 的本地 SAST 工具。Semgrep 出候选,自研跨文件调用图还原请求到达 sink 的路径,LLM 研判可达性并给出修复建议。

**只报有完整 source→sink 路径的漏洞。** 单用户、不接 GitHub、不部署公网服务,全程跑在你自己的机器上。

```
zip → Semgrep 候选 → 调用图 → LLM 研判 → 报告
```

## 功能

**自研跨文件 source→sink 分析**
- Semgrep OSS 的污点分析是函数内的——停在方法边界,所以 service 类里的 SQL sink 只会把一个局部变量报成 "source",完全不提真正喂给它的那个 `@RequestParam`。
- `scanner/callgraph.py` 反着走:从 sink 出发,顺着调用者向上、跨文件,直到抵达一个请求能进来的入口。
- 宽度优先 + 共享 visited,深度由代码决定而不是由代价决定。7 层是真实分层 Spring 应用实测的饱和点。
- 能识别 HTTP handler、消息监听器(Kafka/Rabbit/JMS),以及按父类型判定的 Servlet/Filter 方法。
- MyBatis mapper XML 也在图里:`<mapper namespace>` 给出接口全限定名,`<select id>` 给出方法名,mapper 里的 `${}` 因此能追回到调用它的控制器。

**Semgrep 只出候选,不下结论**
- 只让 Semgrep 干一件事:把可疑的 sink 摆出来,又快又便宜。
- 每条到底是真可达、已被净化,还是误报,交给 LLM 判断,依据是上面那张调用图。
- 每条判定都带 `reachable` / `sanitized` / `confidence` / `reasoning`,外加攻击场景和具体修复方案。

**修复建议要具体,不要套话**
- 复核层直接点名要改哪一行、改成什么——"把 `${sortParam}` 换成 `#{sortParam}`;`ORDER BY` 无法参数化的,用白名单把值映射成固定列名"。
- 可达和不确定的填,没什么可修的留空。

**范围以数据流为准**
- 只有"外部可控数据到达危险操作"才算数。
- 命中代码静态属性的规则——弱哈希、Cookie 少标志位、证书校验被关掉——按 CWE 在花掉一次复核调用之前就被过滤掉。它们是真问题,只是该由别的工具负责。
- 过滤用的是 CWE 黑名单,所以一条从没见过的 vendor 规则第一次命中就被正确归类。

**降噪靠确定性数据,不靠感觉**
- 复制模块自动合并:同一份代码换个包名装两份,只复核一次,报告里指出每一处副本。
- `scripts/rule_stats.py` 给出按规则、按 (规则, 文件) 的命中统计,任何排除都要有证据。
- `rules/ruleset.yml` 内置通用 `exclude_paths`,排掉构建产物、生成代码和 vendored 依赖。

**规则库 vendored 并锁版本**
- `rules/vendor/semgrep-rules` 是锁定的 git submodule,不是实时拉 Registry——换机器、隔一段时间,扫描结果都可复现。
- 在 `rules/ruleset.yml` 里裁剪到服务端 Java/Spring 范围(排除 Android 和 Lambda 专用规则)。
- `rules/custom` 下 5 条自研规则补上实测出的盲区:命令注入、路径穿越、XXE、开放重定向、MyBatis `${}`。
- 每条自研规则都配标注样本,缺正例或缺反例测试直接红。

**LLM 供应商自选**
- 任何 OpenAI 协议兼容的端点:OpenAI、DeepSeek、Kimi、通义千问、智谱 GLM、自建网关。
- 网页里可以存多份配置、随时切换生效项,也可以按次扫描单独指定,不用改 `.env`。

**报告中英双语**
- 中英切换连 LLM 写的正文一起切——判断依据、攻击场景、修复建议,不只是标签。
- 报告可以直接双击打开,不需要起服务。

**一个进程,零构建**
- FastAPI 同时提供 API 和单页前端,只需要跑 `uvicorn`。
- 拖拽上传、可筛选的内联结果、可折叠设置面板、自动跟随系统深浅色。

## 快速开始

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
copy .env.example .env   # 填 OPENAI_API_KEY,或者之后在设置面板里配
uvicorn apps.api.main:app --reload --port 8000
```

打开 `http://localhost:8000`,拖一个 zip 进去,然后看报告。

> 已经 clone 了但没带 `--recurse-submodules`?补一句 `git submodule update --init`。不补的话 `rules/vendor/semgrep-rules` 是空的,扫描会漏掉绝大部分规则。

### 命令行

每个阶段都能独立运行,之间通过 JSON 文件交换数据;逻辑都在可复用的 `scanner/` 包里,和 API 共用。

| 脚本 | 作用 |
| --- | --- |
| `scripts/01_scan.py` | Semgrep → 去重、在范围内的候选 |
| `scripts/02_verify.py` | 调用图 + LLM → 判定 |
| `scripts/03_eval.py` | 拿 `eval/labels.json` 给判定打分 |
| `scripts/04_translate.py` | 补另一种语言(可选) |

`04_translate.py` 是可选的:不跑它,报告和以前完全一样——模型当时用哪种语言回的就显示哪种。

## 测试

```bash
python -m pytest tests/ -v
```

- 213 条单元测试覆盖确定性的那一半:去重、路径处理、上下文提取、调用图、规则集契约,以及 API 的 HTTP 接口。
- 没有任何测试会真的调 LLM——结果不确定又要花钱的调用不该进 CI。
- LLM 的效果单独用 `eval/labels.json` 跟踪。

## 现状

Phase 1 已完成——上传 → 扫描 → 报告全链路跑通——之后一直在迭代。

- `eval/labels.json` 有 19 条人工标注,当前规则集全部能扫到,最近一次全量运行一致率 18/19。
- **复核层在两次完全相同的重跑之间约有 16% 的判定会翻转**,所以 19 条标注上 ±1 的变化属于噪声。引擎改动一律用确定性指标论证:多少条候选找不到入口、多少方法不再被截断、还原了几条调用链。
- 已在一个真实的 13 模块 Maven 项目上实测过,不只跑教学靶场。

完整架构见 `docs/framework.md`,开发规范见 `CLAUDE.md`。

## 许可证

[LGPL-2.1](LICENSE)
