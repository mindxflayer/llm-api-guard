import ast
import logging

logger = logging.getLogger("llm-api-guard")

BUILTINS = {
    "open", "str", "int", "float", "bool", "dict", "list", "set", "tuple",
    "len", "print", "range", "type", "isinstance", "getattr", "hasattr", "setattr",
    "Flask", "request", "app", "FastAPI", "APIRouter", "Django", "__name__", "self", "cls",
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError"
}

class RenameIdentifiersTransformer(ast.NodeTransformer):
    def __init__(self, mapping):
        self.mapping = mapping

    def visit_Name(self, node):
        if node.id in self.mapping:
            return ast.copy_location(ast.Name(id=self.mapping[node.id], ctx=node.ctx), node)
        return self.generic_visit(node)

    def visit_arg(self, node):
        if node.arg in self.mapping:
            return ast.copy_location(ast.arg(arg=self.mapping[node.arg], annotation=node.annotation), node)
        return self.generic_visit(node)

def rename_identifiers(source: str) -> str:
    try:
        tree = ast.parse(source)
    except Exception as e:
        logger.warning(f"rename_identifiers: AST parse failed: {e}")
        return source

    target_vars = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if arg.arg not in BUILTINS and not arg.arg.startswith("__"):
                    target_vars.add(arg.arg)
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id not in BUILTINS and not target.id.startswith("__"):
                            target_vars.add(target.id)

    if not target_vars:
        logger.info("rename_identifiers: No local variables found to rename (no-op)")
        return source

    mapping = {v: f"mut_var_{i+1}" for i, v in enumerate(sorted(target_vars))}
    transformer = RenameIdentifiersTransformer(mapping)
    mutated_tree = transformer.visit(tree)
    ast.fix_missing_locations(mutated_tree)

    mutated_source = ast.unparse(mutated_tree)
    if mutated_source == source:
        logger.info("rename_identifiers: Resulting source identical (no-op)")
        return source
    return mutated_source

class ExtractHelperTransformer(ast.NodeTransformer):
    def __init__(self):
        self.extracted_func = None
        self.extracted = False

    def visit_FunctionDef(self, node):
        if self.extracted or len(node.body) < 2:
            return self.generic_visit(node)

        stmt_idx = -1
        for idx, stmt in enumerate(node.body):
            if isinstance(stmt, ast.Assign):
                stmt_idx = idx
                break

        if stmt_idx == -1:
            return self.generic_visit(node)

        target_stmt = node.body[stmt_idx]
        ref_names = set()
        for sub in ast.walk(target_stmt.value):
            if isinstance(sub, ast.Name):
                ref_names.add(sub.id)

        params = [ast.arg(arg=name) for name in sorted(ref_names)]
        helper_name = f"_helper_extracted_{node.name}"

        helper_body = [ast.Return(value=target_stmt.value)]
        self.extracted_func = ast.FunctionDef(
            name=helper_name,
            args=ast.arguments(
                posonlyargs=[], args=params, kwonlyargs=[], kw_defaults=[], defaults=[]
            ),
            body=helper_body,
            decorator_list=[]
        )

        call_args = [ast.Name(id=p.arg, ctx=ast.Load()) for p in params]
        new_stmt = ast.Assign(
            targets=target_stmt.targets,
            value=ast.Call(func=ast.Name(id=helper_name, ctx=ast.Load()), args=call_args, keywords=[])
        )

        node.body[stmt_idx] = new_stmt
        self.extracted = True
        return node

def extract_to_helper(source: str) -> str:
    try:
        tree = ast.parse(source)
    except Exception as e:
        logger.warning(f"extract_to_helper: AST parse failed: {e}")
        return source

    transformer = ExtractHelperTransformer()
    mutated_tree = transformer.visit(tree)
    if not transformer.extracted or not transformer.extracted_func:
        logger.info("extract_to_helper: Could not extract helper function (no-op)")
        return source

    mutated_tree.body.insert(0, transformer.extracted_func)
    ast.fix_missing_locations(mutated_tree)

    mutated_source = ast.unparse(mutated_tree)
    return mutated_source

class DictAccessStyleTransformer(ast.NodeTransformer):
    def __init__(self):
        self.converted = False

    def visit_Subscript(self, node):
        self.generic_visit(node)
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            self.converted = True
            return ast.Call(
                func=ast.Attribute(value=node.value, attr="get", ctx=ast.Load()),
                args=[node.slice],
                keywords=[]
            )
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.converted = True
                return ast.Subscript(
                    value=node.func.value,
                    slice=node.args[0],
                    ctx=ast.Load()
                )
        return node

def convert_dict_access_style(source: str) -> str:
    try:
        tree = ast.parse(source)
    except Exception as e:
        logger.warning(f"convert_dict_access_style: AST parse failed: {e}")
        return source

    transformer = DictAccessStyleTransformer()
    mutated_tree = transformer.visit(tree)
    if not transformer.converted:
        logger.info("convert_dict_access_style: No dict accesses found to convert (no-op)")
        return source

    ast.fix_missing_locations(mutated_tree)
    return ast.unparse(mutated_tree)

class TryExceptWrapTransformer(ast.NodeTransformer):
    def __init__(self):
        self.wrapped = False

    def visit_FunctionDef(self, node):
        if self.wrapped or not node.body:
            return self.generic_visit(node)

        orig_body = node.body
        try_node = ast.Try(
            body=orig_body,
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id="Exception", ctx=ast.Load()),
                    name="_mut_exc",
                    body=[ast.Raise(exc=ast.Name(id="_mut_exc", ctx=ast.Load()))]
                )
            ],
            orelse=[],
            finalbody=[]
        )
        node.body = [try_node]
        self.wrapped = True
        return node

def wrap_in_try_except(source: str) -> str:
    try:
        tree = ast.parse(source)
    except Exception as e:
        logger.warning(f"wrap_in_try_except: AST parse failed: {e}")
        return source

    transformer = TryExceptWrapTransformer()
    mutated_tree = transformer.visit(tree)
    if not transformer.wrapped:
        logger.info("wrap_in_try_except: No suitable function body found to wrap (no-op)")
        return source

    ast.fix_missing_locations(mutated_tree)
    return ast.unparse(mutated_tree)

class StringFormattingTransformer(ast.NodeTransformer):
    def __init__(self):
        self.converted = False

    def visit_JoinedStr(self, node):
        format_str_parts = []
        format_args = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                format_str_parts.append(str(val.value).replace("{", "{{").replace("}", "}}"))
            elif isinstance(val, ast.FormattedValue):
                format_str_parts.append("{}")
                format_args.append(val.value)
            else:
                return node

        format_string = "".join(format_str_parts)
        self.converted = True
        return ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=format_string),
                attr="format",
                ctx=ast.Load()
            ),
            args=format_args,
            keywords=[]
        )

def change_string_formatting_style(source: str) -> str:
    try:
        tree = ast.parse(source)
    except Exception as e:
        logger.warning(f"change_string_formatting_style: AST parse failed: {e}")
        return source

    transformer = StringFormattingTransformer()
    mutated_tree = transformer.visit(tree)
    if not transformer.converted:
        logger.info("change_string_formatting_style: No f-strings found to convert (no-op)")
        return source

    ast.fix_missing_locations(mutated_tree)
    return ast.unparse(mutated_tree)
