<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

一款面向 Java/Spring 的本地 SAST 工具。Semgrep 找出候选 sink，自研跨文件调用图还原请求到达它的路径，LLM 研判可达性并给出修复建议。

只报有完整 source→sink 路径的漏洞。全程跑在你自己的机器上。

```
zip → Semgrep 候选 → 调用图 → LLM 研判 → 报告
```

## 环境要求

- Python 3.10+
- 任一 OpenAI 协议兼容端点的 API key（OpenAI、DeepSeek、Kimi、通义千问、智谱 GLM，或自建网关）

## 安装

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
```

Semgrep 已在 `requirements.txt` 里锁版本，无需单独安装。

> 已经 clone 了但没带 `--recurse-submodules`？补一句 `git submodule update --init`。不补的话 `rules/vendor/semgrep-rules` 是空的，扫描会漏掉绝大部分规则。

## 配置

```bash
cp .env.example .env
```

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `OPENAI_API_KEY` | 是 | |
| `OPENAI_BASE_URL` | 否 | 仅非 OpenAI 官方端点需要 |
| `OPENAI_VERIFY_MODEL` | 否 | 研判使用的模型 |

也可以在网页里配置多个供应商并按次扫描切换，不用改 `.env`。

## 运行

macOS 和 Linux 用 `./start.sh`，Windows 双击 `start.cmd`。两者都会自动挑一个空闲端口
(8000-8020)、启动服务并打开浏览器。重复启动不会起第二个，会直接复用已经在跑的那个。

在「新建扫描」里拖入项目 zip，它会立刻变成「扫描记录」里的一行，进度、已用时间和实时
日志都在那一行下面。删除一个还在跑的扫描会先把它停掉。报告存在 `data/reports/` 下，
可直接双击打开，不需要起服务。

页面就是这个工具的窗口。启动窗口可以直接关掉，不影响服务；关掉页面服务会自动停止
（扫描进行中除外），「服务」那一节里也有「停止服务」按钮。扫描中途服务被关掉的话，
下次启动会把它标成中断，而不是一直停在「LLM 复核中」。

想自己起服务：

```bash
uvicorn apps.api.main:app --port 8000
```

## 命令行

每个阶段都能独立运行，之间通过 `data/` 下的 JSON 文件交换数据。

```bash
python scripts/01_scan.py --target /path/to/repo
python scripts/02_verify.py --target /path/to/repo
python scripts/03_eval.py
python scripts/04_translate.py          # 可选
```

| 脚本 | 作用 | 产物 |
| --- | --- | --- |
| `01_scan.py` | Semgrep → 去重、在范围内的候选 | `data/candidates.json` |
| `02_verify.py` | 调用图 + LLM → 判定 | `data/verified.json` |
| `03_eval.py` | 拿 `eval/labels.json` 给判定打分 | 标准输出 |
| `04_translate.py` | 补另一种语言 | 原地重写 `data/verified.json` |

常用参数：`--config p/java,p/owasp-top-ten`（01）、`--limit N`（02、04）。

不跑 `04_translate.py`，报告就显示模型当时回答所用的语言。HTML 报告由网页端生成，这些脚本不产出。

## 测试

```bash
python -m pytest tests/ -v
```

378 条单元测试覆盖确定性的那一半——去重、路径处理、上下文提取、调用图、规则集契约，以及 HTTP API。没有任何测试会真的调 LLM；LLM 的效果单独用 `eval/labels.json` 跟踪。

## 实现要点

- **跨文件分析。** Semgrep OSS 的污点分析停在方法边界。`scanner/callgraph.py` 反着走——从 sink 出发，顺着调用者向上、跨文件，直到抵达一个请求能进来的入口。能识别 HTTP handler、消息监听器（Kafka/Rabbit/JMS）、Servlet/Filter 方法，以及 MyBatis mapper XML。
- **Semgrep 只出候选，LLM 下结论。** 每条判定都带 `reachable` / `sanitized` / `confidence` / `reasoning`，外加攻击场景和点名到行的具体修复方案。
- **范围以数据流为准。** 命中代码静态属性的规则——弱哈希、Cookie 少标志位、证书校验被关掉——按 CWE 在花掉一次复核调用之前就被过滤掉。
- **危险级别按 CVSS 定，不看引擎自己的 severity。** Semgrep 只会给 ERROR/WARNING，区分不了未授权 SQL 注入和弱哈希。`scanner/cvss.py` 把每个 CWE 映射到一条 v3.1 基准向量并按公式算分，再由可达性给这个档位定级——被判定不可达的发现无论基准分多高都落到最低档。
- **规则可复现。** `rules/vendor/semgrep-rules` 是锁定的 submodule，在 `rules/ruleset.yml` 里裁剪到服务端 Java/Spring 范围。`rules/custom` 下 5 条自研规则覆盖命令注入、路径穿越、XXE、开放重定向、MyBatis `${}`。

完整架构见 `docs/framework.md`，开发规范见 `CLAUDE.md`。

## 现状

Phase 1 已完成——上传 → 扫描 → 报告全链路跑通。

- `eval/labels.json` 有 19 条人工标注，当前规则集全部能扫到，最近一次全量运行一致率 18/19。
- 复核层在两次完全相同的重跑之间约有 16% 的判定会翻转，所以 19 条标注上 ±1 的变化属于噪声。引擎改动一律用确定性指标论证。
- 已在一个真实的 13 模块 Maven 项目上实测过，不只跑教学靶场。

## 许可证

[LGPL-2.1](LICENSE)
