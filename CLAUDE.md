# CLAUDE.md — sast-local 开发规范

本文件是给 Claude Code(以及任何后续接手开发的人)看的项目级行为准则。写代码前先读这个,和 `docs/framework.md`(架构设计)配合使用——`framework.md` 说"要做成什么样",这份文件说"怎么写、怎么测、什么不能做"。

---

## 1. 语言与技术栈

- **本项目之后所有代码一律用 Python 写**,包括原设计里提到的 `context_builder`(不再用 JavaParser/Java 侧车,改用 Python 方案,比如 `tree-sitter` 或 `javalang`)。这是一条硬约束,不要因为某个语言"更适合"就引入第二语言,除非用户明确改变这条指示。
- Python 版本以 `python3` 命中的版本为准(当前开发机是 3.14),不使用仅在更旧版本可用的写法,但也不要用刚发布还不稳定的最新语法特性。
- 依赖统一写进 `requirements.txt`,新增依赖前先确认是否真的需要,不引入没用上的包。

---

## 2. 代码分隔原则

- **一个脚本只做一件事**,对应 `docs/framework.md` A~G 流程里的一个阶段。不要把"扫描+复核+报告"揉进一个文件。
- `scripts/` 下的编号脚本(`01_scan.py`、`02_verify.py`、`03_eval.py` ...)是**可以独立运行的入口**,每个都要能单独 `python scripts/0N_xxx.py --help` 看到用法。阶段之间通过 `data/*.json` 文件交换数据,不要靠内存里传对象跨脚本共享状态。
- 跨脚本复用的逻辑(路径、hash、JSON 读写)放 `scripts/common.py`,不要每个脚本各写一份。
- Prompt 模板放 `prompts/*.md`,不要把大段 Prompt 字符串硬编码在 `.py` 文件里。
- 一旦某个阶段的脚本超过 ~200 行或职责明显变多(比如 `02_verify.py` 以后要加真正的调用图提取),拆成子模块(比如新建 `verifier/` 包),不要无限往一个文件里堆。

---

## 3. 测试要求

- **确定性逻辑必须有单元测试**:去重(`dedup`)、路径归一化(`relpath`)、dataflow_trace 解析(`extract_source_location`)这类不依赖 LLM 的函数,改动时必须跑测试,不允许"跑一下脚本看输出对不对"就算测过。测试放 `tests/`,用标准库 `unittest` 或 `pytest`(选一个后固定下来,不要混用)。
- **涉及 LLM 调用的部分不能在自动化测试/CI 里真实调用 API**——会产生费用且结果不确定性太高。用 `eval/run_eval.py` + `eval/labels.json` 这套评估基准来验证 LLM 层的效果,而不是把 LLM 调用包进单元测试里 mock 断言。
- 每次改动 `prompts/verify_taint.md` 或换模型,必须重新跑一次 `eval/labels.json` 评估,并在 commit message 里记录准确率变化(比如"agreement 7/9 → 8/9")。不允许"感觉应该变好了"就合并。
- 新增一类漏洞检测能力(比如加了新的 Semgrep 规则)时,`eval/labels.json` 里要跟着补对应的标注样本,不能只加规则不加标注。

---

## 4. 禁止事项

- **禁止把任何 API Key 写进代码、配置文件、commit 里**。`ANTHROPIC_API_KEY` 等必须从环境变量读取,`.env` 文件(如果用)必须在 `.gitignore` 里。发现代码里出现疑似 key 的字符串,先停下来问,不要直接删掉continue。
- **禁止提交 `data/` 目录下的实际内容**(候选结果、上传的 zip、报告、缓存),这些是运行产物不是源码,`.gitignore` 已经处理,不要用 `git add -f` 强行加进去。
- **禁止在扫描/摄取阶段执行目标代码库里的任何脚本或构建命令**(比如自动跑目标项目的 `build.gradle`/`package.json` 脚本),摄取到的代码永远当作不可信数据,只做静态读取和解析。
- **禁止跳过 JSON Schema 校验直接信任 LLM 输出**——`verify.py` 里解析 LLM 返回值必须走 `parse_llm_json` 这类显式校验路径,解析失败要显式标记 `verifier_failed`,不能静默吞掉或者硬凑一个默认值当结果用。
- **禁止破坏性 git 操作**(`reset --hard`、`push --force`、`clean -f`)在没有明确指令的情况下执行,即使只是本地仓库。
- **禁止在没有确认的情况下修改 `docs/framework.md` 里已经定好的架构决策**(比如去重 key、缓存 key 的设计),这些是踩过坑改出来的,要改先说明原因。

---

## 5. 输出标准

- 所有阶段脚本的中间产物(`data/candidates.json`、`data/verified.json`)必须是**格式化过的 JSON**(`indent=2`, `ensure_ascii=False`),方便直接打开读,不要压成一行。
- 脚本的进度/状态信息输出到 `stderr`(`print(..., file=sys.stderr)`),真正的结果数据走文件或 `stdout`,方便管道组合和日志分离。
- LLM 复核的结构化输出字段名固定为 `reachable` / `sanitized` / `confidence` / `reasoning` / `exploit_scenario`,新增字段可以加,但不要改这几个已有字段的名字或类型,下游(`03_eval.py`、后续的 `render.py`)都依赖这个约定。
- commit message 用英文写清楚"做了什么改动 + 为什么"(参考已有的两条提交),不要只写"update" "fix bug" 这种没有信息量的话。
- Python 代码不写文档字符串以外的解释性注释,除非是"为什么这么写"这种非显而易见的原因(比如 `01_scan.py` 里对 dataflow_trace 元组结构的注释,那是因为踩过坑,值得记录)。变量名/函数名本身要写清楚做什么。
