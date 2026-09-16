"""C++ web-framework entry-point discovery.

The supported frameworks expose routes through macros or registration
calls rather than a shared annotation model. This module records only
shapes that name a concrete handler, plus gRPC's server-method signature.
"""
from dataclasses import dataclass
import re

from scanner.callgraph.model import Method


@dataclass(frozen=True)
class EntryReference:
    name: str
    owner: str
    reason: str


@dataclass(frozen=True)
class SyntheticEntry:
    name: str
    reason: str
    start_line: int
    end_line: int


def grpc_entry_reason(method: Method) -> tuple[str, bool]:
    parameters = " ".join(method.parameter_types)
    if (method.return_type.split("::")[-1] == "Status"
            and "ServerContext" in parameters):
        return "gRPC service method", True
    return "", False


def discover_entries(source: bytes) -> tuple[list[EntryReference], list[SyntheticEntry]]:
    text = source.decode("utf-8", errors="replace")
    references: list[EntryReference] = []
    synthetic: list[SyntheticEntry] = []

    for match in re.finditer(
        r"\bENDPOINT(?:_ASYNC)?\s*\(\s*[\"']([A-Z]+)[\"']\s*,\s*"
        r"[\"']([^\"']+)[\"']\s*,\s*([A-Za-z_]\w*)",
        text,
    ):
        method, path, name = match.groups()
        end = _body_end(text, match.end())
        synthetic.append(SyntheticEntry(
            name=name,
            reason=f"Oat++ {method} {path}",
            start_line=_line(text, match.start()),
            end_line=_line(text, end),
        ))

    for match in re.finditer(
        r"\b(?:ADD_METHOD_TO|METHOD_ADD)\s*\(\s*&?(?:(?:[A-Za-z_]\w*::)*"
        r"(?P<owner>[A-Za-z_]\w*)::)?(?P<name>[A-Za-z_]\w*)\s*,\s*"
        r"[\"'](?P<path>[^\"']+)[\"']\s*,\s*(?P<verb>[A-Za-z_]\w*)",
        text,
    ):
        references.append(EntryReference(
            match.group("name"), match.group("owner") or "",
            f"Drogon {match.group('verb').upper()} {match.group('path')}",
        ))

    for match in re.finditer(
        r"\bregisterHandler\s*\(\s*[\"'](?P<path>[^\"']+)[\"']\s*,\s*"
        r"&(?:(?:[A-Za-z_]\w*::)*)(?P<owner>[A-Za-z_]\w*)::"
        r"(?P<name>[A-Za-z_]\w*)",
        text,
    ):
        references.append(EntryReference(
            match.group("name"), match.group("owner"),
            f"Drogon handler {match.group('path')}",
        ))

    for match in re.finditer(r"\bCROW_ROUTE\s*\([^;]+;", text, re.DOTALL):
        statement = match.group(0)
        route = re.search(r"CROW_ROUTE\s*\([^,]+,\s*[\"']([^\"']+)", statement)
        path = route.group(1) if route else "?"
        method = _crow_method(statement)
        calls = list(re.finditer(
            r"\(\s*&?(?:(?P<owner>[A-Za-z_]\w*)::)?"
            r"(?P<name>[A-Za-z_]\w*)\s*\)", statement
        ))
        if calls:
            handler = calls[-1]
            if handler.group("name") not in {"CROW_ROUTE", "methods"}:
                references.append(EntryReference(
                    handler.group("name"), handler.group("owner") or "",
                    f"Crow {method} {path}",
                ))
        lambda_at = statement.find("[]")
        if lambda_at >= 0:
            absolute = match.start() + lambda_at
            end = _body_end(text, absolute)
            synthetic.append(SyntheticEntry(
                name=f"{method} {path}",
                reason=f"Crow {method} {path}",
                start_line=_line(text, absolute),
                end_line=_line(text, end),
            ))
    return references, synthetic


def _crow_method(statement: str) -> str:
    found = re.search(r"HTTPMethod::([A-Za-z]+)", statement)
    return found.group(1).upper() if found else "ANY"


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def _body_end(text: str, offset: int) -> int:
    start = text.find("{", offset)
    if start < 0:
        return offset
    depth = 0
    quote = ""
    escaped = False
    for position in range(start, len(text)):
        char = text[position]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return position
    return len(text)
