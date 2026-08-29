"""B + D: the code context handed to the verify stage.

Split out of core.py once it crossed the size CLAUDE.md section 2 asks for a
split at. The division is by stage: core.py runs semgrep and turns its output
into candidates (A/C), this builds what the LLM actually reads (B/D).

build_caller_context is the D stage docs/framework.md specifies and Phase 1
skipped -- without it the prompt shows one method and asks a question its
callers answer.
"""
from pathlib import Path

from scanner.callgraph import enclosing_method, trace_to_entry_points


CONTEXT_WINDOW = 15  # lines of code above/below each location to include

# A fixed window cuts methods in half. Measured over the VulnerableApp
# corpus, 21 of 51 candidates had their enclosing method truncated by
# CONTEXT_WINDOW, the worst losing 31 lines above the sink -- and what sits
# above a sink is the signature, which is where @RequestParam / @GetMapping
# say whether the value is user-controlled at all. That is the question the
# verify stage is being asked, so the window snaps to the enclosing method.
#
# tree-sitter puts a method's annotations inside its span, so snapping picks
# up @VulnerableAppRequestMapping and friends for free -- checked, not
# assumed. The cap stops one long method from crowding out the call paths
# printed below it; past the cap the head is what is kept, because the head
# is the signature.
MAX_METHOD_LINES = 120
METHOD_HEAD_LINES = 12


def _source_lines(target: Path, rel_path: str) -> list[str] | None:
    full_path = target / rel_path
    if not full_path.exists():
        return None
    return full_path.read_text(encoding="utf-8", errors="replace").splitlines()


def _numbered(lines: list[str], start: int, end: int) -> str:
    """Lines `start`..`end`, 1-based and inclusive, clamped to the file."""
    start = max(1, start)
    end = min(len(lines), end)
    return "\n".join(f"{i:>5} | {lines[i - 1]}" for i in range(start, end + 1))


def read_window(target: Path, rel_path: str, line: int, window: int) -> str:
    lines = _source_lines(target, rel_path)
    if lines is None or line is None:
        return f"(file not found: {rel_path})"
    return _numbered(lines, line - window, line + window)


def read_method_window(target: Path, rel_path: str, line: int, index,
                       window: int = CONTEXT_WINDOW) -> str:
    """The whole method containing `line`, or a plain window around it when
    there is no method to snap to.

    Falls back to read_window whenever the call graph cannot place the line
    -- a field initialiser, a static block, a file that failed to parse --
    so the verify stage never loses context just because the index came up
    empty.
    """
    lines = _source_lines(target, rel_path)
    if lines is None or line is None:
        return f"(file not found: {rel_path})"
    method = enclosing_method(index, rel_path, line) if index is not None else None
    if method is None:
        return _numbered(lines, line - window, line + window)

    if method.end_line - method.start_line + 1 <= MAX_METHOD_LINES:
        return _numbered(lines, method.start_line, method.end_line)

    head_end = method.start_line + METHOD_HEAD_LINES - 1
    tail_start = max(line - window, head_end + 1)
    tail_end = min(line + window, method.end_line)
    if tail_start > tail_end:
        return _numbered(lines, method.start_line, head_end)
    omitted = tail_start - head_end - 1
    return (
        _numbered(lines, method.start_line, head_end)
        + f"\n      | ... {omitted} lines omitted ...\n"
        + _numbered(lines, tail_start, tail_end)
    )


MAX_CALLER_CHAINS = 4  # a shared sink can have many; four is enough to show the pattern
CALLER_WINDOW = 8


def build_caller_context(target: Path, candidate: dict, index) -> str:
    """The call paths by which a request can reach this sink, with the code
    at each entry point.

    This is the half of the picture semgrep cannot supply: its taint analysis
    stops at the method boundary, so a sink reached through a service call
    reports a local variable as its "source" and the verify stage is left
    guessing whether that variable is user-controlled. Where that guessing has
    actually gone wrong on this corpus -- CommandInjection's shared ping
    helper -- the reason becomes visible here: four request handlers call it,
    and they do not all validate first.
    """
    chains = trace_to_entry_points(index, candidate["sink_file"], candidate["sink_line"])
    if not chains:
        return (
            "### Call path\n"
            "No request entry point reaches this method within the searched depth. "
            "Either it is dead code, or it is called from a framework or injection "
            "point this name-based call graph cannot see."
        )
    if chains == [[]]:
        return "### Call path\nThe sink sits directly inside a request handler."

    blocks = ["### Call paths from request entry points to this sink"]
    for chain in chains[:MAX_CALLER_CHAINS]:
        hops = " <- ".join(f"{c.caller.name}() at {c.file}:{c.line}" for c in chain)
        entry = chain[-1].caller
        blocks.append(
            f"\n{hops}\nEntry point: {entry.name}() in {entry.file}, reached via {entry.entry_reason}\n"
            + read_window(target, entry.file, entry.start_line, CALLER_WINDOW)
        )
    if len(chains) > MAX_CALLER_CHAINS:
        blocks.append(f"\n(+{len(chains) - MAX_CALLER_CHAINS} more call paths not shown)")
    return "\n".join(blocks)


def build_context(target: Path, candidate: dict, index=None) -> str:
    sink_block = read_method_window(target, candidate["sink_file"], candidate["sink_line"], index)
    if candidate["source_file"] == candidate["sink_file"] and candidate["source_line"] == candidate["sink_line"]:
        parts = [f"### {candidate['sink_file']} (source == sink)\n{sink_block}"]
    else:
        source_block = read_method_window(target, candidate["source_file"], candidate["source_line"], index)
        parts = [
            f"### Source: {candidate['source_file']}\n{source_block}\n\n"
            f"### Sink: {candidate['sink_file']}\n{sink_block}"
        ]

    if index is not None:
        parts.append(build_caller_context(target, candidate, index))
    return "\n\n".join(parts)


def build_prompt(template: str, candidate: dict, code_context: str) -> str:
    return template.format(
        rule_ids=", ".join(candidate.get("rule_ids", [candidate.get("rule_id", "")])),
        message=" / ".join(candidate.get("messages", [candidate.get("message", "")])),
        cwe=candidate.get("cwe"),
        source_file=candidate["source_file"],
        source_line=candidate["source_line"],
        sink_file=candidate["sink_file"],
        sink_line=candidate["sink_line"],
        code_context=code_context,
    )
