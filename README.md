# sast-local

本地运行的代码安全扫描工具:上传压缩包 → Semgrep 规则库定位候选路径 → LLM 复核可达性 → LLM 生成修复建议报告。

不接 GitHub、不部署公网服务器,单用户本地使用。完整设计见 [`docs/framework.md`](docs/framework.md)。

## 当前阶段

Phase 0:先用脚本验证核心假设(Semgrep 候选 + LLM 复核的准确性),暂不搭前端/API。

## 进度

- [ ] ① Semgrep 规则库跑通,拿到候选列表
- [ ] ②③ 最小版上下文提取 + LLM 复核脚本
- [ ] `eval/labels.json` 标注数据 + 准确率对比
