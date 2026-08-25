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

---

## 用户的工作习惯/偏好(供下次对话参考)

- 会要求先解释清楚"为什么"再动手,尤其是架构选型类问题倾向于先讨论再实现
- 对"简化范围"的决策很干脆(去 GitHub、只本地跑),一旦定了会要求彻底改,不留一半旧设计
- 敏感操作(git commit、push)习惯于先问一句确认再做
- 明确要求过:代码里的 API Key 不要发在对话里,自己在终端设置环境变量
- 这次要求以后所有开发都用 Python(不用 Java 写 context_builder 了,和 v1/v2 框架文档里原本设想的 JavaParser 侧车不一致,后续代码要以 `CLAUDE.md`/`MEMORY.md` 里的最新决策为准,不要照抄 `framework.md` 里"Java 侧车"那部分的具体实现语言)

## 下次对话建议的开场

先看 `MEMORY.md` 的"未完成/下一步入口"一节,大概率是从"用户设置好 API Key,帮忙跑 `02_verify.py` + `03_eval.py`"开始。
