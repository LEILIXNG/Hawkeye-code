# sast-local

本地运行的代码安全扫描工具:上传压缩包 → Semgrep 规则库定位候选路径 → LLM 复核可达性 → LLM 生成修复建议报告。

不接 GitHub、不部署公网服务器,单用户本地使用。完整设计见 [`docs/framework.md`](docs/framework.md)。

## 当前阶段

Phase 1:FastAPI 后端 + 单页前端,完整上传 → 扫描 → 报告流程,LLM 供应商可在 `/settings` 里配置。

## 怎么跑起来

```bash
pip install -r requirements.txt
copy .env.example .env   # 填入 OPENAI_API_KEY(或用 /settings 页面配置)
uvicorn apps.api.main:app --reload --port 8000
```

打开 `http://localhost:8000` 即可上传 zip、发起扫描、查看报告——前端由同一个进程用静态文件方式提供,不需要单独起 Node 服务。

Phase 0 的命令行脚本(`scripts/01_scan.py`、`scripts/02_verify.py`)仍然可用,逻辑已经搬到 `scanner/` 包里给 API 复用,两边共享同一套扫描/复核代码。

## 进度

- [x] ① Semgrep 规则库跑通,拿到候选列表
- [x] ②③ 最小版上下文提取 + LLM 复核脚本
- [x] `eval/labels.json` 标注数据 + 准确率对比(9/9 候选覆盖,一致率 8/9)
- [x] Phase 1:FastAPI + SQLite + 单页前端,完整上传 → 扫描 → 报告闭环跑通
