<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

一款面向服务端 Web 应用的本地 SAST 工具。Semgrep 找出候选 sink，自研跨文件调用图还原请求到达它的路径，LLM 研判可达性并给出修复建议。Java/Spring、Python（Flask、Django、FastAPI）、JavaScript/TypeScript（Express、Koa、NestJS）、Go（net/http、gorilla/mux、chi、gin、echo）、C++、Rust（actix-web、Rocket、axum）、C#（ASP.NET Core 属性路由、MVC 约定路由、Minimal API）、PHP（Laravel 路由门面调用、Symfony/Laravel 的 `#[Route(...)]` 属性和 `@Route(...)` PHPDoc 注解）、Ruby（Rails routes.rb 的按 verb 调用和 `resources` RESTful 宏），以及 Kotlin（Spring Boot 自带的注解路由、Ktor 的 `get("/x") { ... }` 路由构建 DSL）都有完整的跨文件调用图可达性追踪。

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

672 条单元测试覆盖确定性的那一半——去重、路径处理、上下文提取、十组语言的调用图、规则集契约、HTTP API，以及启动器/窗口的生命周期逻辑。没有任何测试会真的调 LLM；LLM 的效果单独用 `eval/labels.json` 跟踪。

## 实现要点

- **跨文件分析，十组语言。** Semgrep OSS 的污点分析停在方法边界。`scanner/callgraph/` 从 sink 反向沿调用者跨文件查找入口。Java、Python 和 JavaScript/TypeScript 保留各自的框架入口识别；Go 识别 net/http、gorilla/mux、chi、gin、echo 的路由注册。C++ 识别 Crow、Drogon、Oat++、gRPC 入口，并利用 tree-sitter 的类型、所有者、重载、模板调用、本地 include 宏和常见函数指针流减少歧义边。Rust 识别 actix-web/Rocket 的属性宏（`#[get(“/x”)]`）和 axum/actix 的路由注册调用（`.route(path, get(handler))`）；所有者关系来自最近的 `impl` 块而非类体，一个类型的 trait 实现可以分散在任意多个 `impl Trait for Type` 块里，全部会累加而不是互相覆盖。C# 识别 ASP.NET Core 自己的属性路由（`[HttpGet("{id}")]`）、MVC 的约定路由（Controller/ControllerBase 派生类上任意 public 方法）和 Minimal API 注册调用（`app.MapGet("/x", handler)`）；`partial class` 分散在多处的基类列表声明会像 Rust 的 trait 实现一样累加。PHP 识别 Symfony/Laravel 共用的 `#[Route(...)]` 属性和更旧的 `@Route(...)` PHPDoc 注解，以及 Laravel 的 `Route::get('/x', $handler)` 门面调用——这是本项目里第一个"处理器几乎总是和注册调用不在同一个文件"的路由注册调用，所以它的具名引用解析是在整个索引里全局查找，而不是像其它语言那样只在注册调用所在文件里找。Ruby 识别 Rails routes.rb 里按 verb 的调用（`get '/x', to: 'ctrl#action'`）和 `resources :name` RESTful 宏（最多展开成七条路由，可以被 `only:`/`except:` 收窄），两者都和 PHP 的 Laravel 门面解析一样全局查找；一个继承 ApplicationController/ActionController::Base 的 public 方法只算弱提示，比 C# 同类的约定路由信号更弱，因为 Rails（不像 ASP.NET MVC）没有 routes.rb 条目就不会真的暴露一个 controller action。Kotlin 对 Spring Boot 的识别和 Java 完全一样，Ktor 则靠它自己的路由构建 DSL——一个以尾随 lambda 代码块结尾的调用（`get("/x") { ... }`）本身就是处理器，`route("/prefix") { ... }` 代码块自己的路径会顺着套了多少层就拼接多少层，一路拼到最内层的 verb 调用上。混合语言项目共用同一张调用图。
- **Semgrep 出候选，LLM 判断数据流。** 请求驱动候选继续使用 `reachable` / `sanitized` / `confidence` / `reasoning` 契约；确定性的 C++ 内存、空指针、敏感信息和文件操作问题由规则验证器判断，标记为”静态确认”，不再交给 LLM 错判 HTTP 请求可达性。
- **混合范围。** 通用静态属性规则仍按 CWE 排除；带确定性验证器的自定义规则可以显式进入静态判定通道。
- **危险级别按 CVSS 定，不看引擎自己的 severity。** Semgrep 只会给 ERROR/WARNING，区分不了未授权 SQL 注入和弱哈希。`scanner/cvss.py` 把每个 CWE 映射到一条 v3.1 基准向量并按公式算分，再由可达性给这个档位定级——被判定不可达的发现无论基准分多高都落到最低档。
- **规则可复现。** `rules/vendor/semgrep-rules` 是锁定的 submodule，覆盖服务端 Java/Spring、Python、JavaScript/TypeScript、Go、Rust、C#、PHP、Ruby 和 Kotlin。C#、PHP 和 Ruby 内置规则的覆盖深度都接近 Java，都没有像 Rust 那样需要补自研规则；Kotlin 内置规则和 Rust 一样薄，只有一条覆盖面较窄但确实是真实检测的命令注入规则，完全没有 SQL 注入规则。`rules/custom` 现在共有 20 条规则，其中 8 条是 `CPP001`–`CPP008`，两条 Rust 自研规则（命令注入、SQL 注入），以及一条 Kotlin 自研 SQL 注入规则（字符串模板插值那一半用 `pattern-regex` 而不是结构化 pattern 匹配，因为确认过 Python f-string 那种"metavariable 写进字符串"的写法在真实 Kotlin 字符串模板上根本匹配不到任何东西）。C++ 规则使用 Semgrep C++ AST；`.h` 只有检测到 C++ 专属内容后才接受其规则结果。

完整架构见 `docs/framework.md`，开发规范见 `CLAUDE.md`。

## 现状

Phase 1 已完成——上传 → 扫描 → 报告全链路跑通。

- `eval/labels.json` 现有 58 条人工标注：19 条 Java、9 条 Python、7 条 JavaScript、8 条 C++（`eval/fixtures/cpp_demo`）、3 条 Rust（`eval/fixtures/rust_demo`）、3 条 C#（`eval/fixtures/csharp_demo`）、3 条 PHP（`eval/fixtures/php_demo`）、3 条 Ruby（`eval/fixtures/ruby_demo`）和 3 条 Kotlin（`eval/fixtures/kotlin_demo`）。C++ 命令执行规则保留请求可达性判断；确定性的 CPP004–CPP008 使用静态判定通道。Rust、C#、PHP、Ruby 和 Kotlin 这五组三条标注走的都是和 Python/JS/Go 一样的请求可达性路径：两个 sink 分别经一个 handler 和一个服务层辅助函数到达，一条是没人调用的孤儿函数。
- C++ 解析只读取源码，不执行构建。必须依赖编译数据库才能确定的条件编译、生成代码、虚调用和复杂函数指针目标仍采取保守结果，不会伪装成完全精确。
- 复核层在两次完全相同的重跑之间约有 16% 的判定会翻转，所以任何一组标注上 ±1 的变化都属于噪声。引擎改动一律用确定性指标论证。
- Java 那部分已在一个真实的 13 模块 Maven 项目上实测过，不只跑教学靶场。

## 许可证

[LGPL-2.1](LICENSE)
