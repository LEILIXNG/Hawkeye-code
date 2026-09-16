"""Source-language classification shared by scanners and call-graph parsers."""
import re
from pathlib import Path


CPP_SUFFIXES = frozenset({".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"})

_CPP_HEADER_SIGNAL = re.compile(
    r"\b(?:namespace|class|template|typename|constexpr|consteval|constinit|nullptr|"
    r"noexcept|decltype|static_cast|dynamic_cast|reinterpret_cast|const_cast|"
    r"thread_local|override|final|concept|requires)\b|"
    r"\bstd\s*::|\b(?:public|private|protected)\s*:|"
    r"#\s*include\s*<(?:(?:string|vector|array|deque|list|map|set|unordered_map|"
    r"unordered_set|memory|optional|variant|tuple|iostream|fstream|sstream|"
    r"algorithm|iterator|functional|utility|type_traits|filesystem|chrono|thread))>"
)


def _code_without_comments_and_literals(source: str) -> str:
    """Mask comments and quoted literals while preserving newlines."""
    out: list[str] = []
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out.extend("  ")
                i += 2
                state = "block_comment"
                continue
            if ch in ('"', "'"):
                quote = ch
                out.append(" ")
                i += 1
                state = "literal"
                continue
            out.append(ch)
        elif state == "line_comment":
            out.append("\n" if ch == "\n" else " ")
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
        else:
            if ch == "\\":
                out.append(" ")
                if nxt:
                    out.append("\n" if nxt == "\n" else " ")
                    i += 2
                    continue
            out.append("\n" if ch == "\n" else " ")
            if ch == quote:
                state = "code"
        i += 1
    return "".join(out)


def is_cpp_path(path: Path) -> bool:
    """Whether `path` should participate in C++ analysis."""
    suffix = path.suffix.lower()
    if suffix in CPP_SUFFIXES:
        return True
    if suffix != ".h":
        return False
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(_CPP_HEADER_SIGNAL.search(_code_without_comments_and_literals(source)))


def iter_cpp_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and is_cpp_path(path):
            yield path
