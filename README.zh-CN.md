<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

本地运行的代码安全扫描工具:上传压缩包 → Semgrep 规则库定位候选的 source→sink 路径 → LLM 复核可达性 → 生成可浏览的报告。

不接 GitHub、不部署公网服务器,单用户本地使用。完整设计见 [`docs/framework.md`](docs/framework.md)。

## 特性

- **Semgrep 找候选 + LLM 复核可达性。** Semgrep 负责又快又便宜地把候选污点路径摆出来,真正费钱费时间的"这条到底能不能打、有没有被净化、是不是误报"交给 LLM 判断,而不是让 LLM 从零分析整个代码库。
- **LLM 供应商随便换。** 任何兼容 OpenAI 协议的接口都能用(OpenAI、DeepSeek、Kimi、通义千问、智谱 GLM、自建网关……)。可以在网页上保存多份供应商配置、随时切换哪份生效,也能在发起某次扫描时单独指定用哪份,不用去改 `.env`。
- **规则库锁版本、不联网拉取。** `rules/vendor/semgrep-rules` 是锁定版本的 git submodule,不是每次实时从 Semgrep Registry 拉取,保证扫描结果在不同机器、不同时间跑出来都一样。`rules/ruleset.yml` 从里面精选出和"服务端 Java/Spring 应用"相关的部分(排除了 Android、AWS Lambda 专用规则)。
- **一个进程,不用额外起服务。** FastAPI 同时提供 API 和单页前端(以静态文件方式挂载),只需要跑 `uvicorn` 这一个进程。
- **网页界面**:拖拽上传 zip、每次扫描的发现可以按"可达/不可达/不确定/复核失败"筛选查看、设置区块可折叠、支持中英文切换——全程自动跟随系统的浅色/深色主题。

## 怎么跑起来

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
copy .env.example .env   # 填入 OPENAI_API_KEY(或者直接用 /settings 页面配置供应商)
uvicorn apps.api.main:app --reload --port 8000
```

如果之前克隆的时候没加 `--recurse-submodules`,补一句 `git submodule update --init`——不然 `rules/vendor/semgrep-rules` 是空的,扫描会漏掉绝大部分规则。

打开 `http://localhost:8000` 即可上传 zip、发起扫描、查看报告。

Phase 0 的命令行脚本(`scripts/01_scan.py`、`scripts/02_verify.py`、`scripts/03_eval.py`)仍然可以独立运行,逻辑都在可复用的 `scanner/` 包里,和 API 共用同一套代码。

## 测试

```bash
python -m pytest tests/ -v
```

确定性逻辑(去重、路径处理、上下文提取、API 的 HTTP 契约)由单元测试覆盖。LLM 复核的效果好坏另外用 `eval/labels.json` 跟踪——自动化测试套件不适合去做真实的、要花钱的、结果还不确定的 API 调用。

## 现状

Phase 1(FastAPI + SQLite + 网页界面,完整的上传 → 扫描 → 报告闭环)已经完成,并且一直在持续打磨:规则库从实时拉取 Registry pack 改成了锁版本的 vendored submodule,LLM 供应商配置做成了可独立保存/切换/按次扫描指定,前端也经过了好几轮重新设计。`eval/labels.json` 里手工标注的 9 条样本全部被当前规则库覆盖,改动 prompt 或换供应商时一致率维持在 8/9——完整架构设计看 `docs/framework.md`,项目自己的开发规范看 `CLAUDE.md`。

## 许可证

[LGPL-2.1](LICENSE)
