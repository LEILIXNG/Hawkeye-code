"""Translation table for the generated report.html.

Kept out of render.py so the renderer stays about layout. Keys that also
exist on the tool page (apps/web/index.html's `I18N`) use the same paths
and the same wording, and both pages read the same `hawkeye-lang`
localStorage key, so switching language on one carries over to the other.

Facet values (vulnerability type, file name, severity) are deliberately
left untranslated -- they come from Semgrep's CWE strings and the scanned
project's own paths, so there is nothing to translate them against.
"""

REPORT_I18N = {
    "zh": {
        "langToggle": "English",
        "reportTitle": "扫描报告",
        "stats": {"reachable": "漏洞总数", "safe": "安全数量", "needsReview": "需要人工复查"},
        "filters": {"all": "全部", "yes": "可达", "no": "不可达", "uncertain": "不确定", "failed": "复核失败"},
        "reachable": {"yes": "可达", "no": "不可达", "uncertain": "不确定", "failed": "复核失败"},
        "facet": {"all": "全部", "type": "按漏洞类型", "file": "按文件", "severity": "按危险程度"},
        "card": {
            "type": "漏洞类型:",
            "rule": "规则说明:",
            "cwe": "CWE:",
            "source": "Source:",
            "confidence": "置信度:",
            "reasoning": "判断依据:",
            "exploit": "攻击场景:",
            "duplicates": "相同代码另见:",
        },
        "empty": {"noFindings": "没有候选发现", "noMatch": "没有匹配这个筛选条件的发现"},
    },
    "en": {
        "langToggle": "中文",
        "reportTitle": "Scan report",
        "stats": {"reachable": "Vulnerabilities found", "safe": "Safe count", "needsReview": "Needs manual review"},
        "filters": {"all": "All", "yes": "Reachable", "no": "Not reachable", "uncertain": "Uncertain", "failed": "Failed"},
        "reachable": {"yes": "Reachable", "no": "Not reachable", "uncertain": "Uncertain", "failed": "Verify failed"},
        "facet": {"all": "All", "type": "By vulnerability type", "file": "By file", "severity": "By severity"},
        "card": {
            "type": "Vulnerability type:",
            "rule": "Rule:",
            "cwe": "CWE:",
            "source": "Source:",
            "confidence": "Confidence:",
            "reasoning": "Reasoning:",
            "exploit": "Exploit scenario:",
            "duplicates": "Same code also at:",
        },
        "empty": {"noFindings": "No candidate findings", "noMatch": "No findings match this filter"},
    },
}

DEFAULT_LANG = "zh"
