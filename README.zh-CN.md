<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="鹰眼代码 logo">
</p>

<h1 align="center">鹰眼代码 · Hawkeye Code</h1>

<p align="center">中文 · <a href="README.md">English</a></p>

本地运行的代码安全扫描工具,**建立在 Semgrep 之上而不是把 Semgrep 当成引擎**:上传压缩包 → Semgrep 摆出候选 → 自研的跨文件调用图还原请求究竟怎么到达每个 sink → LLM 判定可达性 → 生成可浏览的报告。

不接 GitHub、不部署公网服务器,单用户本地使用。完整设计见 [`docs/framework.md`](docs/framework.md)。

## 特性

- **跨文件 source→sink 分析,自研实现。** Semgrep 开源版的污点分析是**过程内**的,到方法边界就停:service 类里的一个 SQL sink,它只会把同方法里的一个局部字符串报成 "source",而真正决定这条路能不能打的、controller 里那个 `@RequestParam`,它一个字都说不出来。`scanner/callgraph.py` 用自己的反向调用图补上这一段——基于 tree-sitter 解析 Java,从 sink 往上追调用方、跨文件一直追到请求入口。把这些调用链加进复核上下文之后,对照标注集的一致率从 9/11 升到 11/11,"不确定"归零。**不依赖任何专有引擎。**
- **Semgrep 只负责找候选,不负责下结论。** Semgrep 的职责就是又快又便宜地把候选污点路径摆出来,仅此而已;"这条到底能不能打、有没有被净化、是不是误报"由 LLM 结合上面的调用链判断,而不是让 LLM 从零分析整个代码库。
- **规则先量后补。** 覆盖率是对着目标代码库实测出来的,量出盲区再用 `rules/custom` 下手写的规则补上。`rules/ruleset.yml` 同时提供 `exclude_rules` / `exclude_paths` 两级降噪开关,`scripts/rule_stats.py` 能按规则、按 (规则, 文件) 两个维度给出命中统计——排除哪条规则是拿证据决定的,不是凭感觉。
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

Phase 0 的命令行脚本(`scripts/01_scan.py`、`scripts/02_verify.py`、`scripts/03_eval.py`、`scripts/04_translate.py`)仍然可以独立运行,逻辑都在可复用的 `scanner/` 包里,和 API 共用同一套代码。

`04_translate.py` 是可选的一步:它给每条发现的判断依据、攻击场景、修复建议补上另一种语言,让报告页的中英文切换连正文一起切,而不只是切标签。不跑这一步,报告和以前完全一样——模型当时用哪种语言回的就显示哪种。

## 测试

```bash
python -m pytest tests/ -v
```

确定性逻辑(去重、路径处理、上下文提取、API 的 HTTP 契约)由单元测试覆盖。LLM 复核的效果好坏另外用 `eval/labels.json` 跟踪——自动化测试套件不适合去做真实的、要花钱的、结果还不确定的 API 调用。

## 现状

Phase 1(FastAPI + SQLite + 网页界面,完整的上传 → 扫描 → 报告闭环)已经完成,并且一直在持续打磨:规则库从实时拉取 Registry pack 改成了锁版本的 vendored submodule,LLM 供应商配置做成了可独立保存/切换/按次扫描指定,前端经过了好几轮重新设计,分析能力也已经越过了"Semgrep 报什么就是什么"——包括针对实测盲区手写的规则,以及上面那套跨文件调用图。

`eval/labels.json` 里手工标注的 11 条样本全部被当前规则库覆盖,最近一次全量复核的一致率是 **11/11**,而调用图落地之前是 8/9。这是一次运行的结果、不是保证(复核层本身有随机性),但那条自评估建立以来一直判错的候选现在判对了,而且调用图正好解释了它此前为什么无解。完整架构设计看 `docs/framework.md`,项目自己的开发规范看 `CLAUDE.md`。

## 许可证

[LGPL-2.1](LICENSE)
