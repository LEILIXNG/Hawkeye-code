# MEMORY.md — 项目进展记录

> 每次开始新一轮开发前先读这个文件,了解现在做到哪、下一步该干什么。这个文件应该在每次有实质进展后更新,不是写一次就不管了。

---

## 当前阶段:Phase 0(验证核心假设,还没有前端/API)

目标:证明"Semgrep 候选 + LLM 复核"这套流程比纯 Semgrep 准、比纯 LLM(dfa_flash.md 那种)快,先不管好不好用。

## 已完成

- [x] `git init` 建好本地仓库(`sast-local/`),无远程,单用户本地开发
- [x] `docs/framework.md` 完整架构设计(去 GitHub 版,纯本地工具,LLM 供应商可配置)
- [x] `scripts/01_scan.py` 跑通:默认规则集已改成 `p/java, p/security-audit, p/owasp-top-ten`(原来默认漏了 `p/java`,而 `p/java` 才是找出被 GitLab SAST 漏掉的 3 类 SQL 注入的关键),对 `VulnerableApp` 项目跑出 72 条原始命中 → 46 条去重后候选,`--dataflow-traces` 跨函数追踪正常工作
- [x] `02_verify.py` 从 Anthropic SDK 切到 **OpenAI Python SDK**(`client.chat.completions.create` + `response_format={"type":"json_object"}`),支持 `OPENAI_BASE_URL`/`OPENAI_VERIFY_MODEL` 切换供应商,并通过 `python-dotenv` 从本地 `.env` 读 key(避免 `setx` 设置的系统环境变量对当前会话进程树不生效的问题)
- [x] `scripts/03_eval.py` 写完并修好一个真 bug:原来按完整相对路径匹配候选和 `labels.json`,但 `--target` 指到 `src/` 目录会导致候选路径缺 `src/` 前缀,9 条标注全部 `NOT FOUND`;改成按文件名(basename)+ 行号匹配,和 `--target` 指到哪一层无关
- [x] `CLAUDE.md` 开发规范
- [x] `tests/test_scan.py`(pytest,10 条用例)覆盖 `01_scan.py` 的确定性函数,全部通过
- [x] **跑完整个 Phase 0 闭环(46 条候选,`glm-4-flash` 模型)**:7/9 标注被扫到并复核,一致率 **6/7(86%)**。两条问题:
  1. `VulnerableAppConfiguration.java:135`(误报测试用例)判断错了——上下文里已经有 `@Value("${spring.datasource.application.password}")` 这行证据,模型还是判成 `reachable: yes`,理由是"a user-provided password"(没对应到代码证据,像是凭变量名猜的)。说明**证据链路本身没问题,是复核模型的推理能力不够**,下一步该换模型对比,不是改上下文提取逻辑。
  2. `CommandInjection.java:47/52` **完全没被 Semgrep 扫到**——`p/java`+`p/security-audit`+`p/owasp-top-ten` 这几个公开 Registry 规则集里没有能命中 `new ProcessBuilder(new String[]{"sh","-c","ping -c 2 "+ipAddress})` 这种模式的规则。对比最早分析的 GitLab SAST 报告,它命中的是 `find_sec_bugs.COMMAND_INJECTION-1`,那是 GitLab 自己维护的移植规则,不在公开 Registry 里。这是真实的规则覆盖缺口,不是脚本 bug。

## 未完成 / 下一步入口

1. **换个更强的模型重跑一次 `02_verify.py` + `03_eval.py`,对比一致率变化**——用来判断 `VulnerableAppConfiguration.java:135` 判错是不是 `glm-4-flash` 这类小模型的通病。改 `.env` 里的 `OPENAI_VERIFY_MODEL`(以及必要的 `OPENAI_BASE_URL`)即可切换,脚本不用改。
2. **补一条能命中 `CommandInjection.java:47/52` 的自定义规则**(`rules/custom/`,现在这个目录还不存在),否则不管 LLM 复核多准,Semgrep 这层根本没把候选交上来,LLM 也无从判断。
3. 根据以上两项结果决定:
   - 如果换模型后一致率明显提升 → 说明思路本身可行,模型选型是可调参数,可以开始投入真正的调用图提取(替代现在"固定行窗口"的简化版 context 提取)
   - 如果换了更强模型还是错 → 该回头改 `prompts/verify_taint.md`,让它更明确要求"逐条对照代码证据,不要凭变量名/命名习惯猜测"
4. 之后按 `docs/framework.md` §8 分阶段计划推进到 Phase 1(FastAPI + 前端)
5. **规则库还没按框架 §2 的设计落地**:目前是硬编码在 `01_scan.py` 里的 Registry 短名,没有 `rules/vendor/`、`rules/custom/`、`rules/ruleset.yml` 这套目录,也没做过"摸底+精简"。第 2 点(补命令注入规则)算是这项工作的第一块,可以顺便把目录结构建起来。

## 关键决策记录(避免以后重新踩坑)

- **去重 key** 用 `(source_file, source_line, sink_file, sink_line)` 四元组,不能只用 sink 位置——CommandInjection 的 Level1~5 共用同一个 sink 行,只按 sink 去重会漏报。
- **LLM 复核触发条件**看 source 语义(是否用户可控),不是看是否跨函数——`VulnerableAppConfiguration.java:135` 是单函数内命中但源头来自配置文件,按"是否跨函数"筛选会被误判为可以跳过复核。
- **缓存 key** 要 hash 完整上下文(整个发给 LLM 的 prompt),不能只 hash sink 那一行代码。
- Semgrep `--dataflow-traces` 的 JSON 结构是 `taint_source: ["CliLoc", [{位置}, "变量名"]]` 这种带标签元组,不是 `{"location": {...}}`,写解析代码前务必先拿真实样本核对结构,不要凭猜测的 schema 名字硬编码字段路径。
- 用 Semgrep Registry 的 `p/java` 直接跑,比 GitLab 托管的 `semgrep-sast` job 覆盖面更全(后者漏掉了 Blind/ErrorBased/UnionBased 三类 SQL 注入,`p/java` 全部找到了)。
- 这个项目**只支持本地 zip 上传,不接 GitHub OAuth**,也**不部署公网服务器**——是有意简化后的决定,不要在没讨论的情况下加回来。
- LLM 供应商要做成前端可配置(Claude/OpenAI 兼容/Ollama),不要写死接 Anthropic。

## 参考文件位置

- 架构设计:`docs/framework.md`
- 开发规范:`CLAUDE.md`
- 测试标注数据来源:本次对话中对 `gl-sast-report.json`(GitLab SAST)的逐条人工分析
- 扫描目标(测试用例):`C:\Users\27297\OneDrive\Desktop\test\VulnerableApp-master\src`(sasanlabs/VulnerableApp,OWASP 教学靶场,漏洞位置已知)
