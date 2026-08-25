# 本地代码安全扫描工具 —— 项目框架

一个本地运行的工具:用户上传本地压缩包 → Semgrep 规则库定位 source-sink 候选路径 → LLM 复核可达性并判定漏洞类型 → LLM 生成带修复建议的报告 → 前端展示。

不接 GitHub、不部署公网服务器,前后端都跑在自己电脑的 localhost 上,单用户使用,不需要登录/鉴权。本文档在上一版基础上做了简化,并保留了此前评审修正的三处准确性问题(成本规则误判、去重 key 错误、缓存粒度不清)。

---

## 0. 总体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                         apps/web (前端, localhost)                 │
│         上传 zip  →  扫描进度  →  报告查看  →  历史记录              │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ REST + SSE (同机 localhost 通信)
┌───────────────────────────────▼──────────────────────────────────┐
│                      apps/api (后端, localhost)                    │
│        上传接收 / 触发扫描 / 查询状态 / 报告下载(无鉴权)              │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ 本地任务队列(进程内,非分布式)
┌───────────────────────────────▼──────────────────────────────────┐
│                          scanner (扫描流程)                        │
│                                                                    │
│  A.解压摄取 → B.Semgrep扫描 → C.候选去重 → D.上下文提取(可选)        │
│      → E.LLM复核 → F.LLM报告生成 → G.渲染落库                      │
└──────────┬─────────────────────────────────────────┬──────────────┘
           │                                          │
┌──────────▼─────────────┐                ┌───────────▼─────────────┐
│ context_builder (本地库) │                │  llm_gateway (本地库)    │
│ 调用图/代码切片,Java 侧车  │                │ LLM 调用封装+缓存+脱敏    │
└─────────────────────────┘                └──────────────────────────┘
```

**相比"连 GitHub 的产品版",这版砍掉的东西**:
- 没有 OAuth、没有 token 存储、没有用户体系——单用户本地工具不需要鉴权
- 没有对象存储(S3)——上传的 zip、生成的报告都存本地磁盘
- 没有 Redis/Celery 这类分布式任务队列——单用户同一时刻通常只跑一个扫描,用进程内的简单任务队列(甚至 FastAPI 的 `BackgroundTasks` + 状态轮询)就够,省掉起一个 Redis 的运维成本
- 数据库用 **SQLite** 而不是 Postgres——单文件、零配置,够用

**保留不变的部分**:
- A~G 扫描流程本身不变
- 沙箱隔离建议保留(上传的 zip 内容仍然不可信,虽然只在本机跑,也建议扫描进程限制资源、不联网,防 zip 炸弹或异常大文件拖垮你自己的电脑)
- `context-builder`、`llm-gateway` 的职责划分不变,只是从"独立服务"降级成"本地库/子进程调用",不需要跨网络的 gRPC/HTTP

---

## 1. 目录结构

```
sast-local/
├── apps/
│   ├── web/                        # 前端(Next.js 或更轻量的 Vite+React 都行,反正只跑本地)
│   │   ├── app/
│   │   │   ├── upload/             # 上传 zip
│   │   │   ├── scans/[id]/         # 扫描进度 + 报告查看
│   │   │   └── history/            # 历史记录
│   │   └── components/report/      # 复用之前设计的严重程度分组+可展开卡片
│   │
│   └── api/                        # FastAPI 后端,`uvicorn` 本地起
│       ├── routers/
│       │   ├── uploads.py          # 接收 zip 上传
│       │   ├── scans.py            # 触发扫描 / 查询状态 / SSE 进度
│       │   ├── reports.py          # 报告获取 / 导出
│       │   └── settings.py         # LLM 供应商配置的增删改查 + 连接测试
│       ├── models.py               # SQLAlchemy(SQLite): Project/Scan/Candidate/Finding/LLMConfig
│       └── local_queue.py          # 进程内任务队列(线程池/asyncio,不是分布式)
│
├── scanner/                        # 扫描流程本体(不再是独立 worker 服务,是被 api 直接调用的模块)
│   ├── stages/
│   │   ├── ingest.py               # A: 解压 zip 到隔离工作目录
│   │   ├── semgrep_scan.py         # B: 跑规则库
│   │   ├── dedup.py                # C: 候选去重(按 source+sink 组合)
│   │   ├── enrich.py               # D: 调 context_builder 补跨函数上下文
│   │   ├── verify.py               # E: 调 llm_gateway 做可达性复核
│   │   ├── narrate.py              # F: 调 llm_gateway 批量生成报告文字
│   │   └── render.py               # G: 渲染报告、写本地磁盘、更新状态
│   └── pipeline.py                 # 编排入口
│
├── context_builder/                 # Java 侧车(JavaParser + JavaSymbolSolver)
│   ├── src/main/java/.../CallGraphService.java
│   └── src/main/java/.../SliceCli.java   # 命令行工具,api 用子进程调用,不需要常驻服务
│
├── llm_gateway/                    # LLM 调用封装(纯 Python 库,被 scanner 直接 import)
│   ├── redact.py                   # 发送前脱敏(密钥/内网域名/PII 正则清洗)
│   ├── cache.py                    # 本地文件缓存(key = 完整上下文的 hash)
│   ├── providers/
│   │   ├── base.py                 # LLMProvider 抽象接口
│   │   ├── claude.py               # Anthropic 官方 SDK
│   │   ├── openai_compatible.py    # 通用 OpenAI 协议适配(DeepSeek/Kimi/通义千问/GLM/自建网关等都走这个)
│   │   └── local_ollama.py         # 本地离线模型
│   ├── config.py                   # 从 LLMConfig 表读取当前生效的供应商配置,实例化对应 provider
│   └── prompts/
│       ├── verify_taint.md
│       └── generate_report.md
│
├── rules/
│   ├── vendor/semgrep-rules/       # git submodule,锁定版本
│   └── custom/                     # 项目自定义规则
│
├── eval/                           # 评估基准
│   ├── benchmark-repos/            # 已标注漏洞位置的测试仓库(可用 VulnerableApp 这类项目)
│   ├── labels.json
│   └── run_eval.py
│
├── data/                           # 本地数据目录(替代对象存储)
│   ├── db.sqlite3
│   ├── uploads/                    # 用户上传的 zip 原文件
│   ├── workspaces/                 # 解压后的临时扫描工作区,扫完清理
│   └── reports/                    # 生成的 report.html / report.json
│
└── docs/
```

---

## 2. 数据模型(SQLite)

```
Project       (id, name, source_zip_filename, created_at)
Scan          (id, project_id, status: queued|ingesting|scanning|verifying|reporting|done|failed,
               started_at, finished_at, error_message)
Candidate     (id, scan_id, rule_id, cwe, owasp,
               source_file, source_line, sink_file, sink_line,
               dedup_key,                 -- hash(source_file+source_line+sink_file+sink_line)
               is_intraprocedural, needs_llm_verify)
Finding       (id, candidate_id, reachable: yes|no|uncertain, sanitized, confidence,
               reasoning, exploit_scenario, severity, verifier_model, verified_at)
Report        (id, scan_id, html_path, json_path, summary)
LLMConfig     (id, name, provider_type: "claude" | "openai_compatible" | "ollama",
               base_url, api_key,           -- 用户自己填的第三方 API
               verify_model, report_model,  -- 复核用/报告生成用可以配不同模型
               is_active, created_at)
```

去掉了 `User` 表(单用户,不需要)。`Project.source_zip_filename` 直接记文件名,不需要区分 `source_type`(反正只剩上传这一种)。

> **对上一版评审问题的修正 ①**:`Candidate.dedup_key` 用 `(source_file, source_line, sink_file, sink_line)` 四元组,不是只用 sink 位置——避免同一个 sink 被多个不同入口(比如 CommandInjection 的 Level1~5)复用时被错误合并。

---

## 3. 核心流程 A~G 详解

### A. 解压摄取(ingest.py)

```
用户上传 zip → 存到 data/uploads/{project_id}.zip
→ 解压到 data/workspaces/{scan_id}/ (临时目录,扫完删除)
```

**必须做的安全校验**(即便只在本机跑,上传的内容仍然不可信):
- 解压前校验路径,拒绝 `../` 形式的 zip-slip
- 解压后总大小、文件数量设上限(防 zip 炸弹拖垮本机磁盘/内存)
- Semgrep 扫描本身只做静态解析不会执行目标代码,风险不大;但如果后续要接支持"编译后再分析"的语言,执行阶段必须加资源限制(CPU/内存/超时),哪怕只在本机跑也不能让一次异常扫描把电脑卡死

### B. Semgrep 扫描(semgrep_scan.py)

- 规则来源:`rules/vendor/`(直接引用 Registry `p/security-audit` 等)+ `rules/custom/`(项目自定义 sanitizer/source 标注)
- 按检测到的语言自动选规则子集,`semgrep --config rules/ruleset.yml --json`

### C. 候选去重(dedup.py)

按 `dedup_key` 四元组去重、合并同位置多条规则命中,标记 `is_intraprocedural`。

### D. 上下文提取(enrich.py → context_builder)

- 只对**跨函数**或**source 不能直接确认是否用户可控**的候选调用 context_builder
- 本地直接用子进程调用 `SliceCli.jar`(命令行工具,输入候选列表,输出切片 JSON),不需要常驻 HTTP 服务,减少本地要维护的进程数量
- BFS 默认 2 层,取不到 sink 时自动加深到 4 层
- Spring 接口注入存在多实现类时,把所有候选实现类的方法体打包给 LLM 判断,而不是静默漏掉

### E. LLM 复核(verify.py → llm_gateway)

**对上一版评审问题的修正 ②(最重要的一处)**:
不用"是否跨函数"判断要不要调 LLM,改成看 source 语义:

```python
def needs_llm_verify(candidate: Candidate) -> bool:
    # 只有当 source 能 100% 静态确认"不是用户可控输入"时才跳过 LLM
    # 例如:source 来自 @Value 读取的配置项、来自硬编码常量
    return not candidate.source_is_confirmed_non_user_input
```

发送给 LLM 前,`llm_gateway/redact.py` 先做一遍脱敏。本地工具场景下代码不出本机是默认选项——`providers/local_ollama.py` 提供完全离线的自部署模型选项;如果用 Claude API,代码片段仍然会发到 Anthropic,这点需要用户知情(建议在扫描前有一个明确提示)。

输出结构化 JSON(`reachable` / `sanitized` / `confidence` / `reasoning` / `exploit_scenario`),Schema 校验失败重试一次,两次失败进 `Finding.reachable = "verifier_failed"`,人工核实。

**缓存修正 ③**:`cache.py` 用本地文件缓存,key 是**整个 EnrichedContext 序列化后的 hash**,不是只 hash sink 那一行。

### F. 报告文字生成(narrate.py)

批量调用(10-20 条打包一次请求),生成"根因说明"+"修复建议",复用之前 HTML 报告的呈现结构。

### G. 渲染落库(render.py)

生成 `data/reports/{scan_id}/report.html` + `report.json`,`Scan.status = done`,前端收到 SSE 推送后跳转到报告页,直接用浏览器打开本地生成的 HTML 即可,不需要额外部署。

---

## 4. 前端关键页面

| 页面 | 功能 |
|---|---|
| `/upload` | 拖拽上传 zip |
| `/scans/[id]` | 实时进度(A~G 七个阶段状态条,SSE 推送) |
| `/scans/[id]/report` | 报告页,复用严重程度分组 + 可展开详情卡片 |
| `/history` | 本机跑过的历史扫描记录 |
| `/settings` | 配置 LLM 供应商(填 Base URL / API Key / 模型名,测试连接) |

---

## 5. LLM 供应商可配置(自己接其他 API)

不写死 Anthropic,让用户在前端自己填第三方 API 的地址和 key。国内常见需求场景是接 DeepSeek、Kimi、通义千问、GLM 这类,它们大多兼容 **OpenAI Chat Completions 协议**,所以只要做好一个通用适配器,不需要每个供应商单独写一份对接代码。

### 5.1 供应商抽象接口

```python
# llm_gateway/providers/base.py
class LLMProvider(ABC):
    @abstractmethod
    def chat(self, messages: list[dict], model: str, response_format: str | None = None) -> str:
        """返回模型原始文本输出,response_format='json' 时要求走结构化输出"""

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """发一个最小请求探活,返回 (是否成功, 错误信息)"""
```

```python
# llm_gateway/providers/openai_compatible.py
class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, base_url: str, api_key: str):
        self.client = OpenAI(base_url=base_url, api_key=api_key)  # openai SDK 本身就支持自定义 base_url

    def chat(self, messages, model, response_format=None):
        resp = self.client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={"type": "json_object"} if response_format == "json" else None,
        )
        return resp.choices[0].message.content

    def test_connection(self):
        try:
            self.chat([{"role": "user", "content": "ping"}], model=self.default_model)
            return True, ""
        except Exception as e:
            return False, str(e)
```

`llm_gateway/config.py` 在扫描开始时读一次 `LLMConfig` 里 `is_active=True` 的那一条,按 `provider_type` 实例化对应 provider,`verify.py`/`narrate.py` 只认 `LLMProvider` 这个抽象接口,不关心背后到底接的是 Claude、DeepSeek 还是自建网关。

### 5.2 前端 `/settings` 页面

一个表单,预置几个常见供应商模板(选了就自动填好 Base URL,用户只要填 Key):

| 供应商 | Base URL(预填) | 说明 |
|---|---|---|
| Claude(官方) | `https://api.anthropic.com` | 走单独的 `claude.py`,协议和其他几个不一样 |
| OpenAI | `https://api.openai.com/v1` | |
| DeepSeek | `https://api.deepseek.com/v1` | |
| 通义千问(兼容模式) | `https://dashscope.aliyuncs.com/compatible-mode/v1` | |
| 自定义 | 用户手填 | 接自建网关/中转 API 都走这个 |
| 本地 Ollama | `http://localhost:11434` | 不需要 Key,完全离线 |

表单字段:供应商模板下拉 → Base URL(自动填,可改)→ API Key → 复核用模型名 → 报告生成用模型名(可以留空复用同一个)→ **"测试连接"按钮**(调 `POST /settings/llm/test`,成功才允许保存)。

### 5.3 API Key 怎么存

单用户本地工具,`LLMConfig.api_key` 直接存 SQLite 问题不大,但还是建议:
- `data/db.sqlite3` 加进 `.gitignore`,避免不小心把 key 提交进版本库
- 前端展示时只显示 key 的前后几位(`sk-ant-****1234`),不要整串明文渲染在页面上
- 提供一个"从环境变量读取"的开关——不想让 key 落盘的用户可以设 `LLM_API_KEY` 环境变量,`llm_gateway/config.py` 优先读环境变量,数据库里的 key 留空即可

### 5.4 API 端点补充

```
GET    /settings/llm            # 获取当前配置
POST   /settings/llm            # 保存配置
POST   /settings/llm/test       # 测试连接(不落库,先验证再保存)
```

---

## 6. 本地怎么跑起来

不需要任何云端部署,两个终端窗口就够:

```bash
# 终端 1:后端
cd apps/api
uvicorn main:app --reload --port 8000

# 终端 2:前端
cd apps/web
npm run dev    # 默认 http://localhost:3000,请求打到 http://localhost:8000
```

想更省事甚至可以只写一个前端页面直接调 `/upload` + `/scans/{id}` 这两个接口用原生 fetch 轮询,不必上完整框架——毕竟只有您自己用,不需要为多用户场景预留复杂度。SQLite 文件、`data/` 目录都在项目根下,整个工具就是一个可以直接 `git clone` 下来跑的自包含项目,不需要 docker-compose、不需要配置数据库连接串。

---

## 7. 评估基准

`eval/` 维护一套带标注答案的测试项目(可以直接拿 `VulnerableApp` 当种子),`eval/run_eval.py` 跑一遍完整 A~G 流程,对照 `labels.json` 算 precision/recall/F1。本地工具也建议保留这一步——改规则、改 Prompt 之后跑一下,确认没有让准确率倒退。

---

## 8. 分阶段落地计划

| 阶段 | 范围 | 关键产出 |
|---|---|---|
| Phase 0(MVP) | 命令行工具,只支持 zip + Java,同步跑完 A~G,无前端 | 先用 `eval/` 验证管线本身准不准 |
| Phase 1 | 加 FastAPI + 本地前端页面,支持完整上传→报告流程 + `/settings` 自定义 LLM 供应商 | 有个能点的本地网页,LLM 不锁死在一家 |
| Phase 2 | 多语言扩展、历史记录对比、报告导出 PDF | 覆盖面和易用性打磨 |

> 如果之后确实需要"扫真实 GitHub 仓库"或"多人协作使用",再把上一版里的 GitHub OAuth + 任务队列 + 对象存储那套加回来即可——两版架构在 A~G 核心流程上是一致的,加回去主要是 apps/api 和基础设施层的改动,scanner/context_builder/llm_gateway 这几块基本不用动。

---

## 9. 和现有方案的定位(汇报/立项用)

| | GitHub Advanced Security(CodeQL) | Snyk Code | GitLab 免费 SAST | 本项目 |
|---|---|---|---|---|
| 跨函数追踪 | ✅(自研引擎) | ✅ | ❌ | ✅(Semgrep 候选 + LLM 补) |
| 使用方式 | 需接入 GitHub 仓库 | 需接入仓库/CI | 需先接 GitLab CI | 本地上传 zip,无需接入任何平台 |
| 修复建议来源 | Copilot(GPT系) | 符号执行+LLM | 无 | LLM,带本项目代码上下文的定制推理 |
| 部署成本 | 企业版收费 | 收费 | 免费但覆盖窄 | 规则免费,按 LLM 调用量付费,可选完全离线(Ollama) |
| 数据出境风险 | 云端 | 云端 | 无(本地引擎) | 用 Claude/GPT 则出境,用 Ollama 则完全不出本机 |
