import os
import ast
from dataclasses import dataclass

@dataclass(frozen=True)
class FunctionRef:
    file_path: str
    name: str

@dataclass
class CallSite:
    caller: FunctionRef
    callee: FunctionRef | None
    node: ast.Call

class ImportVisitor(ast.NodeVisitor):
    def __init__(self):
        self.imports = {}

    def visit_Import(self, node):
        for alias in node.names:
            local_name = alias.asname or alias.name.split('.')[0]
            self.imports[local_name] = ("module", alias.name)

    def visit_ImportFrom(self, node):
        module_name = node.module or ""
        level = node.level
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports[local_name] = ("from_module", module_name, alias.name, level)

class CallsiteVisitor(ast.NodeVisitor):
    def __init__(self, file_path, call_graph):
        self.file_path = file_path
        self.call_graph = call_graph
        self.scope_stack = []
        self.current_function = None

    def visit_ClassDef(self, node):
        class_name = ".".join(self.scope_stack + [node.name])
        class_ref = FunctionRef(file_path=self.file_path, name=class_name)
        self.call_graph.definitions[class_ref] = node
        
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node):
        name = ".".join(self.scope_stack + [node.name])
        func_ref = FunctionRef(file_path=self.file_path, name=name)
        self.call_graph.definitions[func_ref] = node
        
        prev_func = self.current_function
        self.current_function = func_ref
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node):
        name = ".".join(self.scope_stack + [node.name])
        func_ref = FunctionRef(file_path=self.file_path, name=name)
        self.call_graph.definitions[func_ref] = node
        
        prev_func = self.current_function
        self.current_function = func_ref
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node):
        caller = self.current_function or FunctionRef(file_path=self.file_path, name="<module>")
        self.call_graph.raw_calls.append((caller, node, self.file_path))
        self.generic_visit(node)

class CallGraph:
    def __init__(self):
        self.definitions = {}
        self.imports = {}
        self.raw_calls = []
        self.calls = {}
        self.target_repo_path = ""
        self._file_module_map = {}
        self._module_file_map = {}

    def build(self, target_repo_path: str) -> None:
        self.target_repo_path = os.path.abspath(target_repo_path).replace("\\", "/")
        self.definitions = {}
        self.imports = {}
        self.raw_calls = []
        self.calls = {}
        self._file_module_map = {}
        self._module_file_map = {}

        for root, _, files in os.walk(self.target_repo_path):
            if any(p in root for p in ["venv", ".git", ".pytest_cache", ".gemini", "brain"]):
                continue
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.target_repo_path).replace("\\", "/")
                    module_name = self._file_to_module(rel_path)
                    self._file_module_map[rel_path] = module_name
                    self._module_file_map[module_name] = rel_path

        for rel_path in self._file_module_map.keys():
            full_path = os.path.join(self.target_repo_path, rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content, filename=full_path)
            except Exception:
                continue

            imp_visitor = ImportVisitor()
            imp_visitor.visit(tree)
            self.imports[rel_path] = imp_visitor.imports

            call_visitor = CallsiteVisitor(rel_path, self)
            call_visitor.visit(tree)

        for caller, call_node, file_path in self.raw_calls:
            callee = self.resolve_call(call_node, file_path, caller)
            if caller not in self.calls:
                self.calls[caller] = []
            self.calls[caller].append(CallSite(caller=caller, callee=callee, node=call_node))

    def resolve_call(self, call_node: ast.Call, current_module_path: str, caller: FunctionRef = None) -> FunctionRef | None:
        file_path = self._normalize_file_path(current_module_path)
        if file_path not in self._file_module_map:
            return None

        if isinstance(call_node.func, ast.Name):
            name = call_node.func.id
            local_ref = FunctionRef(file_path=file_path, name=name)
            if local_ref in self.definitions:
                return local_ref
            
            init_ref = FunctionRef(file_path=file_path, name=f"{name}.__init__")
            if init_ref in self.definitions:
                return init_ref

            resolved = self._resolve_name_source(name, file_path)
            if resolved:
                src_file, src_name = resolved
                if src_name == "<module>":
                    return FunctionRef(file_path=src_file, name="<module>")
                resolved_ref = FunctionRef(file_path=src_file, name=src_name)
                init_ref = FunctionRef(file_path=src_file, name=f"{src_name}.__init__")
                if init_ref in self.definitions:
                    return init_ref
                return resolved_ref

        elif isinstance(call_node.func, ast.Attribute):
            attr_name = call_node.func.attr
            val = call_node.func.value

            if isinstance(val, ast.Name) and val.id == 'self':
                if caller:
                    parts = caller.name.split('.')
                    if len(parts) > 1:
                        class_name = ".".join(parts[:-1])
                        method_ref = FunctionRef(file_path=file_path, name=f"{class_name}.{attr_name}")
                        if method_ref in self.definitions:
                            return method_ref
                return None

            if isinstance(val, ast.Name):
                var_name = val.id
                resolved = self._resolve_name_source(var_name, file_path)
                if resolved:
                    src_file, src_name = resolved
                    if src_name == "<module>":
                        callee_ref = FunctionRef(file_path=src_file, name=attr_name)
                        if callee_ref in self.definitions:
                            return callee_ref
                        init_ref = FunctionRef(file_path=src_file, name=f"{attr_name}.__init__")
                        if init_ref in self.definitions:
                            return init_ref
                        class_ref = FunctionRef(file_path=src_file, name=attr_name)
                        if class_ref in self.definitions:
                            return class_ref
                    else:
                        class_method_ref = FunctionRef(file_path=src_file, name=f"{src_name}.{attr_name}")
                        if class_method_ref in self.definitions:
                            return class_method_ref

        return None

    def get_function_body(self, func_ref: FunctionRef) -> ast.FunctionDef | None:
        node = self.definitions.get(func_ref)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
        return None

    def _normalize_file_path(self, path: str) -> str:
        path_clean = path.replace("\\", "/")
        if os.path.isabs(path_clean):
            rel = os.path.relpath(path_clean, self.target_repo_path)
            return rel.replace("\\", "/")
        
        if "." in path_clean and not path_clean.endswith(".py") and "/" not in path_clean:
            mapped = self._module_to_file(path_clean)
            if mapped:
                return mapped
        
        return path_clean

    def _file_to_module(self, rel_path: str) -> str:
        path = rel_path.replace("\\", "/")
        if path.endswith(".py"):
            path = path[:-3]
        if path.endswith("/__init__"):
            path = path[:-9]
        return path.replace("/", ".").strip(".")

    def _module_to_file(self, module_name: str) -> str | None:
        if module_name in self._module_file_map:
            return self._module_file_map[module_name]
        
        base = module_name.replace(".", "/")
        py_path = f"{base}.py"
        if os.path.exists(os.path.join(self.target_repo_path, py_path)):
            return py_path
        init_path = f"{base}/__init__.py"
        if os.path.exists(os.path.join(self.target_repo_path, init_path)):
            return init_path
        return None

    def _resolve_relative_module(self, current_module: str, level: int, module_name: str) -> str:
        parts = current_module.split('.')
        if level > 0:
            base_parts = parts[:-level]
            if base_parts:
                base_module = ".".join(base_parts)
                if module_name:
                    return f"{base_module}.{module_name}"
                return base_module
            return module_name
        return module_name

    def _resolve_name_source(self, local_name: str, file_path: str) -> tuple[str, str] | None:
        target_info = self._resolve_name_source_recursive(local_name, file_path, set())
        return target_info

    def _resolve_name_source_recursive(self, local_name: str, file_path: str, visited: set) -> tuple[str, str] | None:
        if file_path in visited:
            return None
        visited.add(file_path)

        local_ref = FunctionRef(file_path=file_path, name=local_name)
        if local_ref in self.definitions:
            return file_path, local_name

        file_imports = self.imports.get(file_path, {})
        if local_name in file_imports:
            imp_type = file_imports[local_name][0]
            if imp_type == "from_module":
                _, module_name, name_in_module, level = file_imports[local_name]
                current_module = self._file_module_map.get(file_path, "")
                abs_module = self._resolve_relative_module(current_module, level, module_name)
                
                submodule_name = f"{abs_module}.{name_in_module}" if abs_module else name_in_module
                submodule_file = self._module_to_file(submodule_name)
                if submodule_file:
                    return submodule_file, "<module>"
                    
                target_file = self._module_to_file(abs_module)
                if target_file:
                    res = self._resolve_name_source_recursive(name_in_module, target_file, visited)
                    if res:
                        return res
            elif imp_type == "module":
                _, module_name = file_imports[local_name]
                target_file = self._module_to_file(module_name)
                if target_file:
                    return target_file, "<module>"
        return None
