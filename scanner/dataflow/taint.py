import os
import ast
import logging
from dataclasses import dataclass
from scanner.dataflow.callgraph import CallGraph, FunctionRef

@dataclass(frozen=True)
class TaintNode:
    file_path: str
    scope_name: str
    kind: str
    name: str
    key: str | None = None

@dataclass
class TaintPath:
    nodes: list[TaintNode]

class TaintTracker:

    def propagate(self, source_var: str, source_function: ast.FunctionDef, callgraph: CallGraph, max_hops: int = 8) -> list[TaintPath]:
        source_ref = None
        for ref, node in callgraph.definitions.items():
            if node is source_function:
                source_ref = ref
                break

        if not source_ref:
            return []

        start_node = TaintNode(
            file_path=source_ref.file_path,
            scope_name=source_ref.name,
            kind="variable",
            name=source_var
        )

        completed_paths = []
        queue = [[start_node]]
        visited_nodes = {start_node}

        while queue:
            current_path = queue.pop(0)
            last_node = current_path[-1]

            hops = len(current_path) - 1
            if hops >= max_hops:
                print(f"taint tracking hop limit ({max_hops}) reached from {source_var} — coverage may be incomplete beyond this point")
                logging.warning(f"taint tracking hop limit ({max_hops}) reached from {source_var} — coverage may be incomplete beyond this point")
                completed_paths.append(TaintPath(nodes=current_path))
                continue

            next_nodes = self._get_transitions(last_node, callgraph)
            if not next_nodes:
                completed_paths.append(TaintPath(nodes=current_path))
                continue

            has_unvisited_expansion = False
            for nxt in next_nodes:
                if nxt not in visited_nodes:
                    visited_nodes.add(nxt)
                    queue.append(current_path + [nxt])
                    has_unvisited_expansion = True

            if not has_unvisited_expansion:
                completed_paths.append(TaintPath(nodes=current_path))

        return completed_paths

    def _get_transitions(self, node: TaintNode, callgraph: CallGraph) -> list[TaintNode]:
        transitions = []
        if node.kind == "variable":
            file_path = node.file_path
            func_name = node.scope_name
            var_name = node.name

            func_ref = FunctionRef(file_path=file_path, name=func_name)
            func_body = callgraph.get_function_body(func_ref)
            if not func_body:
                return transitions

            for sub in ast.walk(func_body):
                if isinstance(sub, ast.Assign):
                    if any(isinstance(n, ast.Name) and n.id == var_name for n in ast.walk(sub.value)):
                        for tgt in sub.targets:
                            if isinstance(tgt, ast.Name):
                                transitions.append(TaintNode(file_path, func_name, "variable", tgt.id))
                            elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                                parts = func_name.split('.')
                                if len(parts) > 1:
                                    class_name = ".".join(parts[:-1])
                                    transitions.append(TaintNode(file_path, class_name, "attribute", tgt.attr))
                            elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                                dict_name = tgt.value.id
                                key_val = None
                                if isinstance(tgt.slice, ast.Constant):
                                    key_val = tgt.slice.value
                                transitions.append(TaintNode(file_path, func_name, "container", dict_name, key_val))

            for sub in ast.walk(func_body):
                if isinstance(sub, ast.Call):
                    for arg_idx, arg in enumerate(sub.args):
                        if any(isinstance(n, ast.Name) and n.id == var_name for n in ast.walk(arg)):
                            callee_ref = callgraph.resolve_call(sub, file_path, func_ref)
                            if callee_ref:
                                callee_body = callgraph.get_function_body(callee_ref)
                                if callee_body:
                                    is_method = False
                                    if len(callee_ref.name.split('.')) > 1:
                                        if callee_body.args.args and callee_body.args.args[0].arg in ("self", "cls"):
                                            is_method = True
                                    target_param_idx = arg_idx + 1 if is_method else arg_idx
                                    if target_param_idx < len(callee_body.args.args):
                                        param_name = callee_body.args.args[target_param_idx].arg
                                        transitions.append(TaintNode(callee_ref.file_path, callee_ref.name, "variable", param_name))

                    for kw in sub.keywords:
                        if any(isinstance(n, ast.Name) and n.id == var_name for n in ast.walk(kw.value)):
                            callee_ref = callgraph.resolve_call(sub, file_path, func_ref)
                            if callee_ref:
                                transitions.append(TaintNode(callee_ref.file_path, callee_ref.name, "variable", kw.arg))

            gets_returned = False
            for sub in ast.walk(func_body):
                if isinstance(sub, ast.Return) and sub.value:
                    if any(isinstance(n, ast.Name) and n.id == var_name for n in ast.walk(sub.value)):
                        gets_returned = True
                        break
            if gets_returned:
                for caller_ref, call_sites in callgraph.calls.items():
                    for call_site in call_sites:
                        if call_site.callee == func_ref:
                            caller_body = callgraph.get_function_body(caller_ref)
                            if caller_body:
                                for sub in ast.walk(caller_body):
                                    if isinstance(sub, ast.Assign):
                                        if any(child is call_site.node for child in ast.walk(sub.value)):
                                            for tgt in sub.targets:
                                                if isinstance(tgt, ast.Name):
                                                    transitions.append(TaintNode(caller_ref.file_path, caller_ref.name, "variable", tgt.id))

        elif node.kind == "attribute":
            file_path = node.file_path
            class_name = node.scope_name
            attr_name = node.name

            for ref, func_body in callgraph.definitions.items():
                if ref.file_path == file_path and ref.name.startswith(f"{class_name}."):
                    for sub in ast.walk(func_body):
                        if isinstance(sub, ast.Assign):
                            reads_attr = False
                            for child in ast.walk(sub.value):
                                if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "self":
                                    if child.attr == attr_name:
                                        reads_attr = True
                                        break
                            if reads_attr:
                                for tgt in sub.targets:
                                    if isinstance(tgt, ast.Name):
                                        transitions.append(TaintNode(file_path, ref.name, "variable", tgt.id))

        elif node.kind == "container":
            file_path = node.file_path
            func_name = node.scope_name
            var_name = node.name
            key_val = node.key

            func_ref = FunctionRef(file_path=file_path, name=func_name)
            func_body = callgraph.get_function_body(func_ref)
            if not func_body:
                return transitions

            for sub in ast.walk(func_body):
                if isinstance(sub, ast.Assign):
                    reads_container = False
                    for child in ast.walk(sub.value):
                        if isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name) and child.value.id == var_name:
                            if key_val is None:
                                reads_container = True
                                break
                            if isinstance(child.slice, ast.Constant) and child.slice.value == key_val:
                                reads_container = True
                                break
                        elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                            if child.func.attr == "get" and isinstance(child.func.value, ast.Name) and child.func.value.id == var_name:
                                if key_val is None:
                                    reads_container = True
                                    break
                                if child.args and isinstance(child.args[0], ast.Constant) and child.args[0].value == key_val:
                                    reads_container = True
                                    break
                    if reads_container:
                        for tgt in sub.targets:
                            if isinstance(tgt, ast.Name):
                                transitions.append(TaintNode(file_path, func_name, "variable", tgt.id))

        return transitions
