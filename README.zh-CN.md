<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

一款面向服务端 Web 应用的本地 SAST 工具。Semgrep 找出候选 sink，自研跨文件调用图还原请求到达它的路径，LLM 研判可达性并给出修复建议。目前 Java/Spring、Python（Flask、Django、FastAPI）和 JavaScript/TypeScript（Express、Koa、NestJS）都支持。

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
(8000-8020)、启动服务，然后打开一个独立的应用窗口（不是浏览器标签页）。重复启动不
会起第二个服务，会直接复用已经在跑的那个。

在「新建扫描」里拖入项目 zip，它会立刻变成「扫描记录」里的一行，进度、已用时间和实时
日志都在那一行下面。删除一个还在跑的扫描会先把它停掉。报告存在 `data/reports/` 下，
可直接双击打开，不需要起服务。LLM 接口被限流（免费端点上常见）不会让扫描直接失败：
已经判定的候选照常保留，来不及判的会标成「未复核」，不会跟「安全」或「不确定」混在一起。

这个窗口就是服务的窗口：关掉它，服务就跟着停（扫描正在跑的话会先弹窗确认）；
「服务」那一节里也有「停止服务」按钮，两种方式都行。扫描中途服务被关掉的话，
下次启动会把它标成中断，而不是一直停在「LLM 复核中」。

想自己起服务：

```bash
uvicorn apps.api.main:app --port 8000
```

### 原生窗口的系统依赖

窗口由 `pywebview` 提供，调用系统自带的浏览器内核，不打包 Chromium。装不上或者
用不了的话会自动退回到打开系统浏览器，功能不受影响，只是少一个独立窗口。

| 平台 | 需要装什么 |
| --- | --- |
| Windows | 一般不需要——WebView2 是 Win10 (1803+) / Win11 自带的 |
| macOS | 用系统自带的 Python 通常不需要；自己装的 Python（Homebrew/python.org）需要 `pip install pyobjc-core pyobjc-framework-Cocoa pyobjc-framework-Quartz pyobjc-framework-WebKit pyobjc-framework-security` |
| Ubuntu/Debian | `sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1` |

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

478 条单元测试覆盖确定性的那一半——去重、路径处理、上下文提取、三种语言的调用图、规则集契约、HTTP API，以及启动器/窗口的生命周期逻辑。没有任何测试会真的调 LLM；LLM 的效果单独用 `eval/labels.json` 跟踪。

## 实现要点

- **跨文件分析，三种语言。** Semgrep OSS 的污点分析停在方法边界。`scanner/callgraph/` 反着走——从 sink 出发，顺着调用者向上、跨文件，直到抵达一个请求能进来的入口。一张共享的图，每种语言各配一个解析器喂进去：Java 那边识别 HTTP handler、消息监听器（Kafka/Rabbit/JMS）、Servlet/Filter 方法，以及 MyBatis mapper XML（含跨模块的 `<mapper namespace>` 解析）；Python 那边识别 Flask/FastAPI 的路由装饰器和 Django 的视图（函数式和基于类的都算）；JavaScript/TypeScript 那边识别 Express/Koa 的路由注册（包括没名字的内联 handler——路由调用自己的参数就是入口点，不一定要有命名声明）和 NestJS 的路由装饰器。一个混合语言的项目会索引进同一张图，而不是好几张互相看不见的图。
- **Semgrep 只出候选，LLM 下结论。** 每条判定都带 `reachable` / `sanitized` / `confidence` / `reasoning`，外加攻击场景和点名到行的具体修复方案。
- **范围以数据流为准。** 命中代码静态属性的规则——弱哈希、Cookie 少标志位、证书校验被关掉——按 CWE 在花掉一次复核调用之前就被过滤掉。
- **危险级别按 CVSS 定，不看引擎自己的 severity。** Semgrep 只会给 ERROR/WARNING，区分不了未授权 SQL 注入和弱哈希。`scanner/cvss.py` 把每个 CWE 映射到一条 v3.1 基准向量并按公式算分，再由可达性给这个档位定级——被判定不可达的发现无论基准分多高都落到最低档。
- **规则可复现。** `rules/vendor/semgrep-rules` 是锁定的 submodule，在 `rules/ruleset.yml` 里裁剪到服务端 Java/Spring、Python（Flask/Django/FastAPI/Pyramid）和 JavaScript/TypeScript（Express、NestJS，以及 Node 后端常用的 JWT、ORM、XML 解析、shell/subprocess 相关库）范围。`rules/custom` 下 5 条自研规则覆盖命令注入、路径穿越、XXE、开放重定向、MyBatis `${}`。

完整架构见 `docs/framework.md`，开发规范见 `CLAUDE.md`。

## 现状

Phase 1 已完成——上传 → 扫描 → 报告全链路跑通。

- `eval/labels.json` 现有 42 条人工标注，覆盖三种语言：19 条 Java（外部的 VulnerableApp 语料，最近一次全量运行一致率 18/19），9 条 Python（`eval/fixtures/python_demo`，一致率 9/9），7 条 JavaScript（`eval/fixtures/express_demo`，一致率 6/7——唯一一条分歧是某次 LLM 回复本身退化成了空判断，confidence 是 0，reasoning 是空的，跟其他六条正常作答的形成对比；不是调用图的问题，也没有为了好看而重跑）。Python 和 JS 这两套语料都直接提交在仓库里，跟 Java 标注不一样，不依赖外部下载就能复现。
- 复核层在两次完全相同的重跑之间约有 16% 的判定会翻转，所以任何一组标注上 ±1 的变化都属于噪声。引擎改动一律用确定性指标论证。
- Java 那部分已在一个真实的 13 模块 Maven 项目上实测过，不只跑教学靶场。

## 许可证

[LGPL-2.1](LICENSE)
