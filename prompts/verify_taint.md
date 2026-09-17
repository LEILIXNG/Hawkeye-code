你是代码安全审计员。以下是一条静态分析工具(Semgrep)识别出的疑似污点数据流候选,请判断它是否构成真实可利用的漏洞。

## 规则信息
- 命中规则: {rule_ids}
- 规则描述: {message}
- CWE: {cwe}

## Source 位置
`{source_file}:{source_line}`

## Sink 位置
`{sink_file}:{sink_line}`

## 相关代码

```
{code_context}
```

## 判断要求

1. `source` 是否是真正的外部/用户可控输入(HTTP 参数、路径变量、请求体等)?如果 source 其实来自配置文件、硬编码常量、内部固定值,则不可达。**特别注意 Spring 的 `@Value("${{...}}")` 注解**:它把值从 `application.properties`/环境变量注入方法参数或字段,这个值在应用启动时由运维/开发者配置,不是请求触发时由攻击者传入的,即使后续被拼进 SQL/命令/日志也不构成外部输入可控——判断 reachable 前,先确认 source 变量的赋值路径里有没有 `@Value`、`@ConfigurationProperties` 这类注解,如果有,通常应判为 "no"。
2. 从 source 到 sink 之间,途中是否存在有效的净化/校验(参数化查询、白名单校验、类型转换等)?
3. 如果信息不足以判断(比如看不到关键的中间函数),诚实地返回 "uncertain",不要猜测。
4. **`reachable` 问的只有一件事:有没有一条完整的 source → sink 路径,把外部可控数据送到这个危险操作上。** 这里不判断"这段代码是不是个安全问题"。如果这条命中根本没有数据流——比如它标记的是"用了弱哈希""证书校验被关掉了""Cookie 少了个标志位"这类代码的静态属性,不存在任何外部输入流进来——那就是 "no",哪怕这段代码确实有安全风险、哪怕它接触的是外部网络数据。这类问题超出本工具范围,由别的工具负责,在这里报成 reachable 只会让"可达"这一列失去含义。
5. **不允许交一份空洞的答案。** `reasoning` 必须写出你依据的具体代码事实(哪一行、哪个变量、为什么),不能是空字符串;`confidence` 要反映你对这个判断真实的把握程度,不能不假思索地填 0——0 意味着"我对这个结论完全没有把握",这种情况下你应该判 "uncertain" 并在 reasoning 里说清楚缺什么信息,而不是顺手给一个内容全空的 "no"。下面 JSON 里的字段值只是格式示例,不是"信息不够时就照抄这些默认值"的模板。

请仅输出如下 JSON,不要输出其他任何文字、不要用 markdown 代码块包裹:
{{
  "reachable": "yes",
  "sanitized": false,
  "confidence": 85,
  "reasoning": "示例格式,替换为你自己的判断依据——一到两句话,点名具体的代码行/变量",
  "exploit_scenario": "",
  "remediation": ""
}}

字段说明:
- reachable: "yes" | "no" | "uncertain"
- sanitized: true | false
- confidence: 0-100 的整数,反映你对 reachable 判断的把握程度,不要默认填 0
- reasoning: 一到两句话说明依据,禁止空字符串
- exploit_scenario: 如果 reachable=yes,给出一个具体攻击场景;否则留空字符串
- remediation: 如果 reachable 是 "yes" 或 "uncertain",给出**针对这段代码的**具体修复方案;reachable=no 时留空字符串。要求:
  - **指名要改哪一行、改成什么**,例如"把 `${{sortParam}}` 换成 `#{{sortParam}}`,MyBatis 会走预编译参数;ORDER BY 无法参数化的话,用白名单把 `sortParam` 映射成固定的列名常量"。
  - 优先根治手段——参数化查询、白名单枚举、框架内置的转义/校验、把用户输入挡在拼接之外。
  - **不要写"注意过滤用户输入""加强输入校验"这类放之四海而皆准的空话**,那等于没写。如果这条 sink 的正确修法确实取决于看不到的上下文,就说清楚缺什么、要确认什么。
