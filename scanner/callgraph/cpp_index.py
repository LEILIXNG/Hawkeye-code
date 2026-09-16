"""Index C++ functions, methods, framework entries and calls."""
from pathlib import Path
import re

from tree_sitter import Node

from scanner.callgraph.cpp_entrypoints import (
    EntryReference,
    SyntheticEntry,
    discover_entries,
    grpc_entry_reason,
)
from scanner.callgraph.cpp_syntax import _arity, _declarator_name, _parser, _text
from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.languages import iter_cpp_files


def index_cpp_workspace(root: Path, index: Index) -> Index:
    parser = _parser()
    references: list[EntryReference] = []
    synthetic: list[tuple[str, SyntheticEntry]] = []
    index_files = list(iter_cpp_files(root))
    cpp_files = {
        str(path.relative_to(root)).replace("\\", "/")
        for path in index_files
    }
    available_files = set(index_files) | set(root.rglob("*.h"))
    sources: dict[Path, bytes] = {}
    macro_sets: dict[Path, set[str]] = {}
    for path in available_files:
        try:
            sources[path.resolve()] = path.read_bytes()
        except OSError:
            continue
    for path, source in sources.items():
        macro_sets[path] = _macro_names(parser.parse(source).root_node, source)

    for path in index_files:
        source = sources.get(path.resolve())
        if source is None:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        tree = parser.parse(source)
        macros = _included_macros(path.resolve(), root.resolve(), sources, macro_sets, set())
        _walk(tree.root_node, source, rel, index, None, Owner(), (), {}, {}, macros)
        file_references, file_synthetic = discover_entries(source)
        references.extend(file_references)
        synthetic.extend((rel, entry) for entry in file_synthetic)
    _resolve_framework_entries(index, references, synthetic, cpp_files)
    _qualify_implicit_member_calls(index, cpp_files)
    _resolve_callback_parameters(index)
    return index


def _walk(node: Node, source: bytes, rel: str, index: Index,
          current: Method | None, owner: Owner, namespace: tuple[str, ...],
          variable_types: dict[str, str], function_refs: dict[str, tuple[str, str]],
          macros: set[str]) -> None:
    if node.type == "namespace_definition":
        name = node.child_by_field_name("name")
        nested = namespace + ((_text(name, source),) if name is not None else ())
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.named_children:
                _walk(child, source, rel, index, current, owner, nested,
                      variable_types, function_refs, macros)
        return

    if node.type in {"class_specifier", "struct_specifier", "union_specifier"}:
        name_node = node.child_by_field_name("name")
        name = _text(name_node, source) if name_node is not None else ""
        qualified = "::".join((*namespace, name)) if name else ""
        bases = _base_types(node, source)
        class_owner = Owner(name=qualified, supertypes=bases)
        if qualified:
            index.supertypes[qualified] = bases
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.named_children:
                _walk(child, source, rel, index, current, class_owner, namespace,
                      variable_types, function_refs, macros)
        return

    if node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        name = _declarator_name(declarator, source)
        params = _find_descendant(declarator, "parameter_list")
        if not name:
            return
        declared_owner = _declarator_owner(declarator, source)
        method_owner = Owner(name=declared_owner) if declared_owner else owner
        parameter_types, parameter_names, parameter_variables = _parameter_info(params, source)
        type_node = node.child_by_field_name("type")
        method = Method(
            file=rel,
            name=name,
            arity=_arity(params),
            return_type=_text(type_node, source) if type_node is not None else "",
            owner=method_owner,
            parameter_types=parameter_types,
            parameter_names=parameter_names,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
        )
        method.entry_reason, method.entry_definitive = grpc_entry_reason(method)
        index.methods.append(method)
        local_types = dict(parameter_variables)
        local_refs: dict[str, tuple[str, str]] = {}
        body = node.child_by_field_name("body")
        if body is not None:
            _collect_bindings(body, source, local_types, local_refs)
            for child in body.named_children:
                _walk(child, source, rel, index, method, method_owner, namespace,
                      local_types, local_refs, macros)
        return

    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        name, target_owner, receiver_is_self = _call_target(
            function, source, current, variable_types, function_refs
        )
        if name and name not in macros:
            index.calls.append(Call(
                file=rel,
                callee=name,
                arity=_arity(args),
                line=node.start_point[0] + 1,
                caller=current,
                receiver_is_self=receiver_is_self,
                target_owner=target_owner,
                argument_types=_argument_types(args, source, variable_types),
                argument_symbols=_argument_symbols(args, source),
            ))

    for child in node.named_children:
        _walk(child, source, rel, index, current, owner, namespace,
              variable_types, function_refs, macros)


def _resolve_framework_entries(index: Index, references: list[EntryReference],
                               synthetic: list[tuple[str, SyntheticEntry]],
                               cpp_files: set[str]) -> None:
    for reference in references:
        for method in index.methods:
            if method.file not in cpp_files or method.name != reference.name:
                continue
            if reference.owner and _short(method.owner.name) != _short(reference.owner):
                continue
            method.entry_reason = reference.reason
            method.entry_definitive = True

    for rel, entry in synthetic:
        found = next((
            method for method in index.methods
            if method.file == rel and method.name == entry.name
            and method.start_line <= entry.start_line <= method.end_line
        ), None)
        if found is None:
            found = Method(
                file=rel,
                name=entry.name,
                arity=0,
                start_line=entry.start_line,
                end_line=entry.end_line,
                entry_reason=entry.reason,
                entry_definitive=True,
            )
            index.methods.append(found)
        else:
            found.entry_reason = entry.reason
            found.entry_definitive = True
        for call in index.calls:
            if call.file == rel and entry.start_line <= call.line <= entry.end_line:
                call.caller = found


def _collect_bindings(node: Node, source: bytes, variable_types: dict[str, str],
                      function_refs: dict[str, tuple[str, str]]) -> None:
    if node.type == "function_definition":
        return
    if node.type == "declaration":
        type_node = node.child_by_field_name("type")
        base = _text(type_node, source) if type_node is not None else ""
        for child in node.named_children:
            if child.type not in {"init_declarator", "identifier", "pointer_declarator",
                                  "reference_declarator", "function_declarator"}:
                continue
            declarator = child.child_by_field_name("declarator") if child.type == "init_declarator" else child
            name = _declarator_name(declarator, source)
            if name:
                variable_types[name] = _type_with_declarator(base, declarator, source)
            if child.type == "init_declarator" and name:
                value = child.child_by_field_name("value")
                target = _symbol_reference(value, source)
                if target:
                    function_refs[name] = target
    elif node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and left.type == "identifier":
            target = _symbol_reference(right, source)
            if target:
                function_refs[_text(left, source)] = target
    for child in node.named_children:
        _collect_bindings(child, source, variable_types, function_refs)


def _parameter_info(node: Node | None, source: bytes) -> tuple[
        tuple[str, ...], tuple[str, ...], dict[str, str]]:
    if node is None:
        return (), (), {}
    types: list[str] = []
    names: list[str] = []
    variables: dict[str, str] = {}
    for parameter in node.named_children:
        if parameter.type == "variadic_parameter":
            types.append("...")
            names.append("")
            continue
        if parameter.type != "parameter_declaration":
            continue
        type_node = parameter.child_by_field_name("type")
        declarator = parameter.child_by_field_name("declarator")
        base = _text(type_node, source) if type_node is not None else ""
        declared = _type_with_declarator(base, declarator, source)
        types.append(declared)
        name = _declarator_name(declarator, source)
        names.append(name)
        if name:
            variables[name] = declared
    return tuple(types), tuple(names), variables


def _type_with_declarator(base: str, declarator: Node | None, source: bytes) -> str:
    if declarator is None:
        return base
    text = _text(declarator, source)
    suffix = ""
    if "*" in text:
        suffix += " *"
    if "&&" in text:
        suffix += " &&"
    elif "&" in text:
        suffix += " &"
    return (base + suffix).strip()


def _argument_types(node: Node | None, source: bytes,
                    variable_types: dict[str, str]) -> tuple[str, ...]:
    if node is None:
        return ()
    return tuple(_expression_type(child, source, variable_types)
                 for child in node.named_children)


def _argument_symbols(node: Node | None, source: bytes) -> tuple[str, ...]:
    if node is None:
        return ()
    symbols: list[str] = []
    for child in node.named_children:
        target = _symbol_reference(child, source)
        symbols.append("::".join(part for part in target if part) if target else "")
    return tuple(symbols)


def _expression_type(node: Node, source: bytes, variable_types: dict[str, str]) -> str:
    if node.type in {"string_literal", "concatenated_string"}:
        return "string-literal"
    if node.type == "char_literal":
        return "char"
    if node.type == "number_literal":
        text = _text(node, source).lower()
        return "double" if any(marker in text for marker in (".", "e", "f")) else "int"
    if node.type in {"true", "false"}:
        return "bool"
    if node.type == "identifier":
        return variable_types.get(_text(node, source), "")
    if node.type in {"cast_expression", "new_expression"}:
        type_node = node.child_by_field_name("type")
        return _text(type_node, source) if type_node is not None else ""
    return ""


def _call_target(node: Node | None, source: bytes, current: Method | None,
                 variable_types: dict[str, str],
                 function_refs: dict[str, tuple[str, str]]) -> tuple[str, str, bool]:
    if node is None:
        return "", "", False
    if node.type in {"identifier", "field_identifier"}:
        name = _text(node, source)
        owner, target = function_refs.get(name, ("", name))
        return target, owner, False
    if node.type == "template_function":
        name = node.child_by_field_name("name")
        return _call_target(name, source, current, variable_types, function_refs)
    if node.type in {"qualified_identifier", "scoped_identifier"}:
        scope = node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        return (
            _declarator_name(name, source),
            _text(scope, source) if scope is not None else "",
            False,
        )
    if node.type == "field_expression":
        argument = node.child_by_field_name("argument")
        field = node.child_by_field_name("field")
        name = _declarator_name(field, source)
        receiver = _text(argument, source) if argument is not None else ""
        is_self = receiver in {"this", "*this"}
        target_owner = current.owner.name if is_self and current is not None else variable_types.get(receiver, "")
        return name, target_owner, is_self
    return "", "", False


def _symbol_reference(node: Node | None, source: bytes) -> tuple[str, str] | None:
    if node is None:
        return None
    if node.type == "identifier":
        return "", _text(node, source)
    if node.type in {"qualified_identifier", "scoped_identifier"}:
        scope = node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        return (_text(scope, source) if scope is not None else "",
                _declarator_name(name, source))
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        return "", _declarator_name(field, source)
    if node.type in {"pointer_expression", "unary_expression"} and node.named_children:
        return _symbol_reference(node.named_children[-1], source)
    return None


def _declarator_owner(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    if node.type in {"qualified_identifier", "scoped_identifier"}:
        scope = node.child_by_field_name("scope")
        if scope is not None:
            return _text(scope, source)
    for child in node.named_children:
        found = _declarator_owner(child, source)
        if found:
            return found
    return ""


def _base_types(node: Node, source: bytes) -> tuple[str, ...]:
    clause = next((child for child in node.named_children
                   if child.type == "base_class_clause"), None)
    if clause is None:
        return ()
    return tuple(_text(child, source).removeprefix("public ").removeprefix("protected ")
                 .removeprefix("private ").strip()
                 for child in clause.named_children)


def _macro_names(node: Node, source: bytes) -> set[str]:
    names: set[str] = set()
    for current in _nodes(node):
        if current.type in {"preproc_function_def", "preproc_def"}:
            name = current.child_by_field_name("name")
            if name is not None:
                names.add(_text(name, source))
    return names


def _included_macros(path: Path, root: Path, sources: dict[Path, bytes],
                     macro_sets: dict[Path, set[str]], seen: set[Path]) -> set[str]:
    if path in seen:
        return set()
    seen = seen | {path}
    found = set(macro_sets.get(path, ()))
    source = sources.get(path, b"").decode("utf-8", errors="replace")
    for included in re.findall(r'^\s*#\s*include\s*"([^"]+)"', source, re.MULTILINE):
        candidates = ((path.parent / included).resolve(), (root / included).resolve())
        child = next((candidate for candidate in candidates if candidate in sources), None)
        if child is not None:
            found |= _included_macros(child, root, sources, macro_sets, seen)
    return found


def _resolve_callback_parameters(index: Index) -> None:
    additions: list[Call] = []
    existing = list(index.calls)
    for method in index.methods:
        callback_parameters = {}
        for position, name in enumerate(method.parameter_names):
            invoked = [call for call in existing
                       if name and call.caller is method and call.callee == name]
            if invoked:
                callback_parameters[position] = invoked[0].arity
        if not callback_parameters:
            continue
        for incoming in existing:
            if incoming.callee != method.name or incoming.caller is None:
                continue
            for position, callback_arity in callback_parameters.items():
                if position >= len(incoming.argument_symbols):
                    continue
                symbol = incoming.argument_symbols[position]
                if not symbol:
                    continue
                parts = symbol.split("::")
                additions.append(Call(
                    file=incoming.file,
                    callee=parts[-1],
                    arity=callback_arity,
                    line=incoming.line,
                    caller=incoming.caller,
                    target_owner="::".join(parts[:-1]),
                ))
    index.calls.extend(additions)


def _qualify_implicit_member_calls(index: Index, cpp_files: set[str]) -> None:
    signatures = {
        (method.owner.name, method.name, method.arity)
        for method in index.methods
        if method.owner.name
    }
    for call in index.calls:
        if (call.file not in cpp_files or call.target_owner or call.caller is None
                or not call.caller.owner.name):
            continue
        if (call.caller.owner.name, call.callee, call.arity) in signatures:
            call.target_owner = call.caller.owner.name


def _nodes(node: Node):
    yield node
    for child in node.named_children:
        yield from _nodes(child)


def _find_descendant(node: Node | None, wanted: str) -> Node | None:
    if node is None:
        return None
    if node.type == wanted:
        return node
    for child in node.named_children:
        found = _find_descendant(child, wanted)
        if found is not None:
            return found
    return None


def _short(name: str) -> str:
    return name.split("::")[-1]
