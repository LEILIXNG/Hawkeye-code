"""Optional high-confidence validators for C++ Semgrep candidates.

Most rules need no second pass. A rule opts in through
`metadata.hawkeye_validator`; registered validators can reject an AST match
when the pinned engine deliberately normalizes away a distinction the rule
needs, such as scalar versus array delete.
"""
import re
from pathlib import Path
from typing import Callable

from scanner.callgraph.cpp_syntax import _declarator_name, _parser
from scanner.languages import _code_without_comments_and_literals


Validator = Callable[[dict, Path], bool]
VALIDATORS: dict[str, Validator] = {}


def validator(name: str):
    def register(func: Validator) -> Validator:
        VALIDATORS[name] = func
        return func
    return register


def passes_cpp_validator(result: dict, target: Path) -> bool:
    name = (result.get("extra", {}).get("metadata", {})
            .get("hawkeye_validator"))
    if not name:
        return True
    names = name if isinstance(name, list) else [name]
    return all(registered and registered(result, target)
               for registered in (VALIDATORS.get(item) for item in names))


def _result_path(result: dict, target: Path) -> Path:
    path = Path(result["path"])
    return path if path.is_absolute() else target / path


def _walk(node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


@validator("standard-function-call")
def _standard_function_call(result: dict, target: Path) -> bool:
    """Reject an unqualified call shadowed by a local function or macro."""
    try:
        source = _result_path(result, target).read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
    except (KeyError, TypeError, ValueError, OSError):
        return False
    matched = source[start:end].decode("utf-8", errors="replace").lstrip()
    call = re.search(r"([A-Za-z_]\w*)\s*\(", matched)
    if not call:
        return False
    # Explicit global/std qualification is an intentional library call.
    if matched.startswith("::") or matched.startswith("std::"):
        return True
    called = call.group(1)

    for node in _walk(_parser().parse(source).root_node):
        if node.type == "function_definition":
            if _declarator_name(node.child_by_field_name("declarator"), source) == called:
                return False
        elif node.type == "declaration":
            for child in _walk(node):
                if child.type == "function_declarator" and _declarator_name(child, source) == called:
                    return False
        elif node.type in {"preproc_function_def", "preproc_def"}:
            name = node.child_by_field_name("name")
            if name is not None and source[name.start_byte:name.end_byte].decode() == called:
                return False
    return True


@validator("new-delete-mismatch")
def _new_delete_mismatch(result: dict, target: Path) -> bool:
    """Confirm the nearest assignment uses the opposite allocation form."""
    try:
        source = _result_path(result, target).read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
    except (KeyError, TypeError, ValueError, OSError):
        return False

    # Semgrep offsets are byte offsets. Decoding the whole file first changes
    # their positions on CRLF files because Python normalizes newlines in text
    # mode, and it also makes offsets drift after non-ASCII source text.
    matched = source[start:end].decode("utf-8", errors="replace")
    deletion = re.search(r"\bdelete\s*(\[\s*\])?\s*([A-Za-z_]\w*)", matched)
    if not deletion:
        return False
    delete_array = deletion.group(1) is not None
    pointer = re.escape(deletion.group(2))

    code = _code_without_comments_and_literals(
        source[:start].decode("utf-8", errors="replace")
    )
    assignments = list(re.finditer(rf"\b{pointer}\s*=\s*([^;]+);", code))
    if not assignments:
        return False
    rhs = assignments[-1].group(1).strip()
    if not re.match(r"^new\b", rhs):
        return False
    allocation_array = bool(re.search(r"\[[^\]]*\]", rhs))
    return allocation_array != delete_array
