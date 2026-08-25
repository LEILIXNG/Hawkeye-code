# MEMORY.md — 项目进展记录

> 每次开始新一轮开发前先读这个文件,了解现在做到哪、下一步该干什么。这个文件应该在每次有实质进展后更新,不是写一次就不管了。

---

## 当前阶段:Phase 0(验证核心假设,还没有前端/API)

目标:证明"Semgrep 候选 + LLM 复核"这套流程比纯 Semgrep 准、比纯 LLM(dfa_flash.md 那种)快,先不管好不好用。

## 已完成

- [x] `git init` 建好本地仓库(`sast-local/`),无远程,单用户本地开发
- [x] `docs/framework.md` 完整架构设计(去 GitHub 版,纯本地工具,LLM 供应商可配置)
- [x] `scripts/01_scan.py` 跑通:对 `VulnerableApp` 项目用 `p/java` 规则集扫描,60 条原始命中 → 37 条去重后候选,`--dataflow-traces` 跨函数追踪正常工作
- [x] `scripts/02_verify.py` 写完但**还没实际跑过**(需要 `ANTHROPIC_API_KEY`,用户说先不运行)
- [x] `scripts/03_eval.py` 写完,配合 `eval/labels.json`(9 条人工核实过的标注,来自本次对话早期对 GitLab SAST 报告的逐条分析)
- [x] `CLAUDE.md` 开发规范

## 未完成 / 下一步入口

1. **跑 `02_verify.py`**:用户需要先自己设置 `ANTHROPIC_API_KEY` 环境变量(不要让用户把 key 发在对话里),然后执行:
   ```bash
   cd scripts
   python 02_verify.py --target "/c/Users/27297/OneDrive/Desktop/test/VulnerableApp-master/src" --limit 10
   ```
   建议先用 `--limit 10` 小批量跑,确认 Prompt/解析没问题,再跑全量(37 条)。
2. **跑 `03_eval.py`** 看一致率:
   ```bash
   python 03_eval.py
   ```
   重点看 `VulnerableAppConfiguration.java:135` 这条(expected=no)有没有被 LLM 正确识别为不可达——这是之前手动分析出的关键误报案例,是验证"LLM 复核有没有用"的试金石。
3. 根据评估结果决定:
   - 如果一致率高(比如 ≥8/9):说明思路可行,可以开始往真正的调用图提取(替代现在"固定行窗口"的简化版 context 提取)投入
   - 如果一致率低:先别急着加功能,回去改 `prompts/verify_taint.md`,重新跑评估,直到稳定
4. 之后按 `docs/framework.md` §8 分阶段计划推进到 Phase 1(FastAPI + 前端)

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
