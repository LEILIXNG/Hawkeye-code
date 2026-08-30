把下面这份漏洞复核结论翻译成{target_language}。**输出必须是{target_language},这一条没有例外。**

这是一份静态代码安全扫描报告里的三个字段,读者是需要动手修这个漏洞的开发者。

```json
{payload}
```

翻译要求:

1. **只翻译,不要改变结论、不要补充内容、不要删减**。原文说"不确定",译文就得说"不确定",不能变成肯定或否定。
2. **代码标识符、文件名、行号、方法名、CWE 编号、SQL/Java 关键字一律保持原样不译**——比如 `sortParam`、`GradingFillingToolController.java:215`、`#{{}}`、`getCanonicalPath()`、`CWE-89` 这些。读者要拿它们去代码里搜。
3. 保留原文的 Markdown 反引号和代码片段格式。
4. 空字符串的字段,译文也返回空字符串。
5. 术语按安全领域惯例:source/sink 可保留英文,"污点"对应 taint,"可达"对应 reachable,"净化/消毒"对应 sanitize。
6. **原文是什么语言都不影响输出语言。** 不要因为"原文读起来已经通顺"就把原文原样返回——原样返回等于没做这件事。三个字段的译文全部要是{target_language}。

请仅输出如下 JSON,不要输出其他任何文字、不要用 markdown 代码块包裹:
{{
  "reasoning": "",
  "exploit_scenario": "",
  "remediation": ""
}}
