# MEMORY.md — 项目进展记录

> 每次开始新一轮开发前先读这个文件,了解现在做到哪、下一步该干什么。这个文件应该在每次有实质进展后更新,不是写一次就不管了。

---

## 当前阶段:Phase 1(FastAPI + 前端,完整上传→报告闭环)

Phase 0 目标(已达成):证明"Semgrep 候选 + LLM 复核"这套流程比纯 Semgrep 准、比纯 LLM(dfa_flash.md 那种)快。
Phase 1 目标:按 `docs/framework.md` §8,加 FastAPI 后端 + 本地前端页面,支持完整上传→报告流程 + `/settings` 自定义 LLM 供应商。

## 已完成

- [x] `git init` 建好本地仓库(`sast-local/`),无远程,单用户本地开发
- [x] `docs/framework.md` 完整架构设计(去 GitHub 版,纯本地工具,LLM 供应商可配置)
- [x] `scripts/01_scan.py` 跑通:默认规则集已改成 `p/java, p/security-audit, p/owasp-top-ten`(原来默认漏了 `p/java`,而 `p/java` 才是找出被 GitLab SAST 漏掉的 3 类 SQL 注入的关键),对 `VulnerableApp` 项目跑出 72 条原始命中 → 46 条去重后候选,`--dataflow-traces` 跨函数追踪正常工作
- [x] `02_verify.py` 从 Anthropic SDK 切到 **OpenAI Python SDK**(`client.chat.completions.create` + `response_format={"type":"json_object"}`),支持 `OPENAI_BASE_URL`/`OPENAI_VERIFY_MODEL` 切换供应商,并通过 `python-dotenv` 从本地 `.env` 读 key(避免 `setx` 设置的系统环境变量对当前会话进程树不生效的问题)
- [x] `scripts/03_eval.py` 写完并修好一个真 bug:原来按完整相对路径匹配候选和 `labels.json`,但 `--target` 指到 `src/` 目录会导致候选路径缺 `src/` 前缀,9 条标注全部 `NOT FOUND`;改成按文件名(basename)+ 行号匹配,和 `--target` 指到哪一层无关
- [x] `CLAUDE.md` 开发规范
- [x] `tests/test_scan.py`(pytest,10 条用例)覆盖 `01_scan.py` 的确定性函数,全部通过
- [x] **跑完整个 Phase 0 闭环(46 条候选,`glm-4-flash` 模型)**:7/9 标注被扫到并复核,一致率 6/7(86%)。发现两条问题:模型误判 `VulnerableAppConfiguration.java:135`(证据齐了但推理错),以及 `CommandInjection.java:47/52` 完全没被公开 Registry 规则扫到。
- [x] **补了自定义规则**`rules/custom/java/command-injection.yml`(纯 pattern 规则,不是 taint 模式——按框架设计,Semgrep 这层只管把候选摆出来,可达性判断交给 LLM 复核层),接进 `01_scan.py` 的 `DEFAULT_CONFIGS`。重跑后 48 条候选,**9/9 标注全部被扫到,一致率提升到 8/9(89%)**。规则覆盖缺口已解决。
- [x] `rules/` 目录结构起了个头(`rules/custom/java/`),框架 §2 设计的 `rules/vendor/`(submodule)、`rules/ruleset.yml`、"摸底+精简"还没做。

## Phase 1 已完成(2026-08-26)

**实现范围**(有意收窄的 MVP,细节见下面的决策记录):
- `scanner/` 包:把 Phase 0 脚本里的确定性逻辑(`core.py` 扫描/去重、`verify.py` LLM 调用+缓存、`render.py` 报告渲染、`ingest.py` zip 解压防护、`pipeline.py` 编排 A→B→C→E→G)搬成可 import 的模块,`scripts/01_scan.py`/`02_verify.py` 现在是薄 CLI 包装,行为不变(10 条旧测试原样通过)。
- `llm_gateway/`:`providers/base.py` 抽象接口 + `providers/openai_compatible.py`(覆盖 OpenAI/DeepSeek/Kimi/通义千问/GLM/自建网关——它们都走同一个 Chat Completions 协议)+ `config.py`(从 DB 里的 `LLMConfig` 或 `.env` 兜底构建 provider)。
- `apps/api/`:FastAPI + SQLite(SQLAlchemy),`models.py` 对应 `docs/framework.md` §2 的 Project/Scan/Candidate/Finding/Report/LLMConfig。路由:`POST /uploads`、`POST /scans`(触发扫描,`BackgroundTasks` 跑,一次一个,不用分布式队列)、`GET /scans/{id}`(轮询状态)、`GET /scans/{id}/report(.html|.json)`、`GET/POST /settings/llm` + `POST /settings/llm/test`、`GET /projects` + `GET /projects/{id}/scans`(历史记录)。
- `apps/web/index.html`:单文件原生 fetch 页面(上传+轮询+设置表单+历史列表),FastAPI 用 `StaticFiles` 直接挂载在 `/`,一个 `uvicorn` 进程就是完整的本地工具,不需要 Node/Next.js。
- 新增单元测试:`tests/test_ingest.py`(zip-slip、文件数/体积上限)、`tests/test_render.py`(汇总统计)、`tests/test_api.py`(HTTP 契约,用 `TestClient` + 隔离的临时 SQLite,不触发真实 semgrep/LLM 调用)。测试总数 10 → 28,全通过。
- **真实跑通一次完整闭环做验证**:起 `uvicorn` → 上传只含 `CommandInjection.java` 的 zip → 触发扫描 → 轮询到 `verifying` 状态。过程中揪出一个新 bug(见下面决策记录的 `--no-git-ignore` 那条),修完后候选数量和 Phase 0 命令行跑出来的完全一致(2 条,行号 47/52)。最后一步卡在智谱 GLM 免费模型限流(HTTP 429,"该模型当前访问量过大"),这是外部 API 的问题,不是代码 bug——`scan.status=failed` + `error_message` 正确记录下来了,失败处理路径本身是验证通过的。

## 未完成 / 下一步入口

> **这是一个手动设置的记忆点**——对话在这里暂停,等用户决定下一步方向。下次直接从这一节接着做,不用重新读全文件。

Phase 1 主体闭环已经跑通(卡在外部 API 限流,不是代码问题),几个有意收窄/搁置的点,供下次决定要不要补:

1. **换个模型 / 换个时间点,把一次 `POST /scans` 真正跑到 `status=done`**,肉眼确认 `report.html`、`Candidate`/`Finding`/`Report` 表都落库正确——这次卡在 GLM 限流,逻辑路径本身(ingest→scan→verify→render→DB 写入)已经手动跑过大半段,但没有一次完整跑到底的 `done` 状态。
2. **`VulnerableAppConfiguration.java:135` 那条模型推理错误**(Phase 0 遗留,见"关键决策记录"),还没排查,Phase 1 不影响这个问题。
3. **`docs/framework.md` 里 Phase 1 设想的东西,这次有意没做**(不是漏了,是判断"单用户本地工具"用不上,记在下面决策记录里,别下次误以为是漏项):SSE 推送进度(用轮询代替)、Claude 官方 SDK/Ollama 两个 provider(只做了 OpenAI 协议兼容的,覆盖了实际在用的 GLM/DeepSeek 这类)、narrate.py 单独的报告文字生成 LLM pass(报告直接复用 verify 阶段的 reasoning/exploit_scenario)、apps/web 用 Next.js(改成单文件原生页面)、`reports.py` 单独路由文件(和 scans.py 合并了,因为共享同一个后台任务和 DB 模型)。
4. 规则库按框架 §2 设计补完整(`rules/vendor/` submodule、摸底+精简噪音规则)——Phase 0 就搁置的,Phase 1 也没动。

## 关键决策记录(避免以后重新踩坑)

- **去重 key** 用 `(source_file, source_line, sink_file, sink_line)` 四元组,不能只用 sink 位置——CommandInjection 的 Level1~5 共用同一个 sink 行,只按 sink 去重会漏报。
- **LLM 复核触发条件**看 source 语义(是否用户可控),不是看是否跨函数——`VulnerableAppConfiguration.java:135` 是单函数内命中但源头来自配置文件,按"是否跨函数"筛选会被误判为可以跳过复核。
- **缓存 key** 要 hash 完整上下文(整个发给 LLM 的 prompt),不能只 hash sink 那一行代码。
- Semgrep `--dataflow-traces` 的 JSON 结构是 `taint_source: ["CliLoc", [{位置}, "变量名"]]` 这种带标签元组,不是 `{"location": {...}}`,写解析代码前务必先拿真实样本核对结构,不要凭猜测的 schema 名字硬编码字段路径。
- 用 Semgrep Registry 的 `p/java` 直接跑,比 GitLab 托管的 `semgrep-sast` job 覆盖面更全(后者漏掉了 Blind/ErrorBased/UnionBased 三类 SQL 注入,`p/java` 全部找到了)。
- 这个项目**只支持本地 zip 上传,不接 GitHub OAuth**,也**不部署公网服务器**——是有意简化后的决定,不要在没讨论的情况下加回来。
- LLM 供应商要做成前端可配置(Claude/OpenAI 兼容/Ollama),不要写死接 Anthropic。
- API Key 用本地 `.env` 文件(python-dotenv 加载),不要指望 `setx` 设的系统环境变量——`setx` 只对"之后新启动的进程"生效,这个开发会话所在的进程树是设置之前就起的,读不到。
- **`.env.example` 是模板,不能填真实值**——之前用户手滑直接改了 `.env.example`(会被 git 追踪)而不是 `.env`,虽然当场用 `git checkout` 挡住了没让它进提交历史,但那个 key 已经在对话记录里出现过,后续都建议换新 key。以后看到疑似真实 key 出现在被追踪的文件里,第一反应是检查 `git status`/`git log` 有没有真的提交进去。
- Semgrep 自定义规则不用非得写成 `mode: taint` 才有用——像 `rules/custom/java/command-injection.yml` 这种纯 pattern 规则,只要能把候选摆出来就够了,可达性判断交给 LLM 复核层,不需要 Semgrep 自己证明数据流全程可达。
- **`run_semgrep` 必须带 `--no-git-ignore`**——Semgrep 默认在 git 仓库里跑的时候用 `git ls-files` 枚举待扫文件,这意味着任何被 `.gitignore` 排除的文件都会被静默跳过。`sast-local/` 自己就是个 git 仓库,而 `data/workspaces/{scan_id}/`(API 解压 zip 用的临时目录)正好在 `data/*` 这条 gitignore 规则下面——不加这个 flag 的话,Phase 1 API 触发的每一次扫描都会得到 0 条候选,现象是"明明文件在,Semgrep 却什么都没扫到"。Phase 0 的命令行脚本因为扫描目标通常在这个仓库之外(比如 `C:\...\VulnerableApp-master\src`)才没踩到这个坑。定位过程:直接在 `data/workspaces/{id}` 上手动跑 `semgrep --verbose`,看到 "Scanning 0 files tracked by git" 这行字才反应过来。
- **LLM 复核的缓存 key 从 `sha256(prompt)` 改成了 `sha256(f"{model}:{prompt}")`**——原来换模型复测同一批候选时会命中旧模型的缓存结果,拿到的其实是别的模型的判断。这个改动会让 Phase 0 阶段攒的旧缓存文件全部失效(不影响正确性,只是第一次会重新调用 API),`data/llm_cache/` 本来就是 gitignore 掉的运行产物,不用手动清。

## 参考文件位置

- 架构设计:`docs/framework.md`
- 开发规范:`CLAUDE.md`
- 测试标注数据来源:本次对话中对 `gl-sast-report.json`(GitLab SAST)的逐条人工分析
- 扫描目标(测试用例):`C:\Users\27297\OneDrive\Desktop\test\VulnerableApp-master\src`(sasanlabs/VulnerableApp,OWASP 教学靶场,漏洞位置已知)
- Phase 1 入口:`uvicorn apps.api.main:app --reload --port 8000`,浏览器打开 `http://localhost:8000`
- Phase 1 代码:`scanner/`(可复用的扫描/复核/渲染逻辑)、`llm_gateway/`(供应商适配)、`apps/api/`(FastAPI+SQLite)、`apps/web/index.html`(单页前端)
