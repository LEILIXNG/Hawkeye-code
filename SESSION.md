# SESSION.md — 对话上下文记录

> 记录这个项目是怎么从"帮忙接 GitLab CI"一路聊到现在这个本地工具的,方便下次接着聊的时候不用重新解释背景。这是对话历史的摘要,不是项目文档——项目本身的设计看 `docs/framework.md`,进展看 `MEMORY.md`。

---

## 对话脉络(按时间顺序)

**1. 起点:给 VulnerableApp 项目接 GitLab CI 免费 SAST**
- 项目是 `sasanlabs/VulnerableApp`(Java/Spring,OWASP 教学靶场),推到了 `gitlab.com/usm-group4/USM-project`
- 排查了三轮 CI 报错:`gradlew` 缺可执行权限 → `gradle-wrapper.jar` 被 `.gitignore` 的 `*.jar` 规则误伤,从没提交过 → `spotlessJavascript` 依赖 npm,CI 镜像没有,加 `-x spotlessCheck` 跳过
- 最终 pipeline 跑通,拿到 `gl-sast-report.json`(GitLab 用的是 Semgrep 引擎,不是最初以为的 SpotBugs)

**2. 解读扫描结果,产出第一份 HTML 报告**
- 29 条发现(5 严重/5 高危/12 中危/7 低危),做成可展开的 HTML 报告(Artifact)
- 逐条读源码判断"教学演示模块 / 误报 / 真实需要修"三类,标了 26 组结果:14 教学演示、7 建议真实修复(主要是全项目没有 CSRF 防护)、5 误报(比如 Cookie Secure 属性其实写对了,只是 Semgrep 判断不了运行时条件)

**3. 对比另一份 DFA 报告(`dfa_flash.md`,deepseekv4flash 模型跑的纯 LLM 数据流分析)**
- DFA 找出 86 条(49 真漏洞+5待复核+32确认安全),远多于 Semgrep 的 29 条
- 核实出一个关键差距:**GitLab SAST 完全漏掉了 `BlindSQLInjectionVulnerability`/`ErrorBasedSQLInjectionVulnerability`/`UnionBasedSQLInjectionVulnerability` 三个类共 7 处 SQL 注入**,DFA 全部找到

**4. 讨论技术方案空间**
- GitLab Duo 的漏洞解释/修复功能背后是 Claude,付费功能
- 市面上其他"SAST + LLM"方案:Snyk DeepCode AI Fix、Semgrep Assistant、GitHub Copilot Autofix、ZeroPath、Vulnhuntr(仅支持 Python,这个项目是 Java,用不了)
- 定下自己做的方向:**Semgrep 找候选(便宜快)+ LLM 只复核候选(不从零扫全仓库,这是 dfa_flash.md 跑 62 分钟的根本原因)**

**5. 框架设计 v1(纯 pipeline,发到 `llx 的github/framework.md`)**
- A~G 七阶段:规则扫描→上下文提取→LLM复核→LLM报告生成
- 用户做了一次犀利评审,揪出三个问题:①调用图对 Spring DI/AOP 的局限没说清 ②"是否跨函数"作为要不要调 LLM 的判断标准是错的(会放过 `VulnerableAppConfiguration.java:135` 这种单函数内的误报)③去重只按 sink 位置会吞掉 CommandInjection Level1~5 这种共享 sink 的不同发现

**6. 框架设计 v2(产品化,`github-sast-platform.md`)**
- 加了前端(Next.js)+ 后端(FastAPI)+ GitHub OAuth 直连仓库 + 异步任务队列 + 沙箱隔离,对标 GitHub Advanced Security/Snyk

**7. 简化决策:去掉 GitHub,改纯本地工具**
- 用户判断"不接 GitHub,只本地上传 zip"更简单,同意后大改:去掉 OAuth/鉴权/Postgres/Redis/S3,换成 SQLite + 本地磁盘 + 进程内队列
- 又加了一个需求:**LLM 供应商前端可配置**,不锁死 Anthropic——设计了 `LLMProvider` 抽象接口 + `openai_compatible.py` 通用适配器,覆盖 DeepSeek/Kimi/通义千问这类国内常用的 OpenAI 协议兼容供应商

**8. 落地:建仓库、写 Phase 0 脚本**
- `git init` 建了 `sast-local/` 本地仓库(无远程)
- 讨论过 git 回档操作(`restore`/`reset --soft`/`--hard`/`stash`)
- 写了 `01_scan.py`(跑通,验证了 Semgrep `--dataflow-traces` 的 JSON 结构是带标签元组,第一版解析代码写错了,已修好)、`02_verify.py`(写完,用户要求先不运行,等自己设好 `ANTHROPIC_API_KEY` 再跑)、`03_eval.py`
- `eval/labels.json` 种子数据直接复用第 2 步里人工核实过的 9 条标注
- 创建 `CLAUDE.md`(开发规范:Python-only、脚本按 A~G 阶段拆分、LLM 部分不能进自动化测试只能走 eval 基准、禁止硬编码 key/提交 data 目录/静默吞掉 LLM 解析失败)

**9. LLM 接口从 Anthropic 换成 OpenAI SDK,补单元测试**
- `02_verify.py` 改用 OpenAI Python SDK + `response_format=json_object`,顺带支持 `OPENAI_BASE_URL`/`OPENAI_VERIFY_MODEL`(为了能接 DeepSeek/智谱这类国内供应商)
- 写了 `tests/test_scan.py`(pytest,10 条),覆盖 `01_scan.py` 的确定性函数,专门补了一条"CommandInjection 共享 sink 不同 source 不能被误合并"的回归测试

**10. 设置 API Key 的一波三折**
- `setx` 设置的系统环境变量对当前会话的进程树不生效(因为进程树在设置之前就已经起了),改成用本地 `.env` 文件(python-dotenv 加载),彻底绕开这个问题
- 用户两次把真实 key 明文贴出来:第一次是截图,第二次是**手滑把 key 填进了 `.env.example`(会被 git 追踪的模板文件)而不是 `.env`**,当场用 `git checkout` 挡住没让它进提交历史,但两次 key 都已经在对话记录里出现过,建议后续都去对应平台撤销重新生成
- 用户用的是**智谱 GLM**(`open.bigmodel.cn`),不是 OpenAI 官方,模型是 `glm-4-flash`

**11. 跑通 Phase 0 完整闭环,补了一条自定义规则**
- 第一轮:46 候选,7/9 标注被扫到,一致率 6/7(86%)。两个真实发现:①`VulnerableAppConfiguration.java:135` 模型判错(证据齐了,`glm-4-flash` 还是把配置来源的密码当成用户输入)②`CommandInjection.java:47/52` 完全没被公开 Registry 规则集扫到(`p/java`+`p/security-audit`+`p/owasp-top-ten` 都没有对应规则,GitLab 托管的 `find_sec_bugs.COMMAND_INJECTION-1` 不在公开 Registry 里)
- 顺手修了 `03_eval.py` 一个真 bug:按完整路径匹配候选和标注,因为 `--target` 指到 `src/` 目录导致候选路径少一层前缀,9 条全 `NOT FOUND`;改成按文件名+行号匹配
- 补了 `rules/custom/java/command-injection.yml`(纯 pattern 规则,不是 taint 模式,按框架设计 Semgrep 只管摆候选、可达性交给 LLM 复核层),接进默认配置。第二轮:48 候选,**9/9 标注全部覆盖,一致率提升到 8/9(89%)**
- 在这个节点设置了记忆点(`MEMORY.md` 里标了 checkpoint),等用户决定下一步是排查最后那条模型误判,还是推进到 Phase 1 前端

**12. 推进到 Phase 1(2026-08-26)**
- 用户直接说"接着做 Phase 1",没有先讨论排查模型误判那条 checkpoint——按 `docs/framework.md` §8 的范围(FastAPI + 本地前端 + `/settings` 供应商配置)动手,但做了几处有意收窄(细节在 `MEMORY.md` 的决策记录里):不做 SSE 用轮询、不做 Next.js 用单文件原生页面、只做 OpenAI 协议兼容的 provider(够用,GLM/DeepSeek 都走这条)、不单独做 narrate.py 报告文字生成(复用 verify 阶段已有的 reasoning/exploit_scenario)
- 把 Phase 0 脚本里的确定性逻辑拆成可 import 的 `scanner/` 包(`core.py`/`verify.py`/`render.py`/`ingest.py`/`pipeline.py`),`scripts/01_scan.py`/`02_verify.py` 改成薄 CLI 包装,原有 10 条测试不改代码就全部通过
- 新增 `llm_gateway/`(provider 抽象 + OpenAI 兼容适配器)、`apps/api/`(FastAPI+SQLite,models 对应框架 §2 数据模型)、`apps/web/index.html`(单页前端)
- 补了三份新测试文件(`test_ingest.py`/`test_render.py`/`test_api.py`),测试数 10→28
- 真机起 `uvicorn` 手动跑通一次完整闭环做验证时,发现并修了一个新 bug:`run_semgrep` 没加 `--no-git-ignore`,导致 API 触发的扫描在 `data/workspaces/{id}` 这种被自己仓库 `.gitignore` 掉的目录下跑,Semgrep 默认用 `git ls-files` 枚举文件,直接得到 0 候选。加上这个 flag 后候选数量和 Phase 0 命令行结果完全吻合(CommandInjection.java:47/52)
- 最后一步(`POST /scans` 跑到 `status=done`)卡在智谱 GLM 免费模型限流(HTTP 429),这是外部问题不是代码 bug,失败处理路径(`status=failed` + `error_message`)本身验证是对的
- 这次没有再单独设一个"等用户选"的 checkpoint——Phase 1 主体已经做完,`MEMORY.md` 的"未完成/下一步入口"列的是几个搁置项和"用真实成功的一次 done 状态收尾"这个待办,不是决策分叉点

---

## 用户的工作习惯/偏好(供下次对话参考)

- 会要求先解释清楚"为什么"再动手,尤其是架构选型类问题倾向于先讨论再实现
- 对"简化范围"的决策很干脆(去 GitHub、只本地跑),一旦定了会要求彻底改,不留一半旧设计
- 敏感操作(git commit、push)习惯于先问一句确认再做
- 明确要求过:代码里的 API Key 不要发在对话里,自己在终端设置环境变量
- 这次要求以后所有开发都用 Python(不用 Java 写 context_builder 了,和 v1/v2 框架文档里原本设想的 JavaParser 侧车不一致,后续代码要以 `CLAUDE.md`/`MEMORY.md` 里的最新决策为准,不要照抄 `framework.md` 里"Java 侧车"那部分的具体实现语言)
- 遇到"NOT FOUND"/异常结果不要急着归因成"上游工具漏扫了",先怀疑自己脚本的路径处理/解析逻辑——这次两次真实 bug(`--dataflow-traces` 解析、`03_eval.py` 路径匹配)都是这么揪出来的
- 对截图/粘贴内容里可能带真实密钥这件事很敏感,一旦发现会主动要求撤销重新生成,不会因为"反正只是本地工具"就降低警惕

## 下次对话建议的开场

直接看 `MEMORY.md` 的"未完成/下一步入口"一节。Phase 1(FastAPI + 单页前端 + `/settings`)主体已经做完并手动验证过大半段流程,不是决策阻塞点了——列的是几个搁置项(Phase 0 遗留的模型误判、框架文档里有意没做的 SSE/Next.js/多 provider 等)和一个待办(真机把一次扫描完整跑到 `status=done`,上次卡在 GLM 限流)。
