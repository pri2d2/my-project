"""
AST-based analysis of student crypto code.

Walk the Python AST to:
  1. Detect crypto library imports and build a local alias table.
  2. Identify crypto operations (key gen, cipher init, encrypt, hash, etc.)
  3. Track variable assignments that carry crypto values.
  4. Build a directed graph of nodes + edges representing data flow.
"""

from __future__ import annotations

import ast
import textwrap
from typing import Optional

from cryptoviz.analyzer.crypto_patterns import (
    FUNCTION_PATTERNS,
    METHOD_PATTERNS,
    KNOWN_CRYPTO_IMPORTS,
)
from cryptoviz.graph.models import (
    CryptoError,
    EdgeData,
    EdgeType,
    GraphData,
    NodeData,
    NodeType,
    Severity,
)


class _NameResolver:
    """Tracks import aliases so we can resolve `AES` → `Crypto.Cipher.AES`."""

    def __init__(self) -> None:
        # local_name → canonical module string
        self._aliases: dict[str, str] = {}

    def record_import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[-1]
            self._aliases[local] = alias.name

    def record_import_from(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            full = f"{module}.{alias.name}" if module else alias.name
            self._aliases[local] = full

    def canonical(self, name: str) -> str:
        return self._aliases.get(name, name)

    def module_alias(self, name: str) -> str:
        """Return the last component of the canonical path (e.g. 'AES')."""
        canon = self.canonical(name)
        # Check if the canonical form is a known crypto import
        for k, v in KNOWN_CRYPTO_IMPORTS.items():
            if canon == k or canon.startswith(k):
                return v
        return canon.split(".")[-1]


class CryptoASTParser(ast.NodeVisitor):
    """
    Visits every node in the student's AST and builds a GraphData.
    """

    def __init__(self, source_code: str, filename: str = "<unknown>") -> None:
        self._source_lines = source_code.splitlines()
        self._filename = filename
        self._resolver = _NameResolver()
        self._graph = GraphData(source_file=filename)
        self._node_counter = 0
        self._edge_counter = 0
        # variable_name → node_id   (last assignment that produced a crypto value)
        self._var_to_node: dict[str, str] = {}
        # node_id → NodeData
        self._nodes: dict[str, NodeData] = {}

    # ── public API ────────────────────────────────────────────────────────────

    def parse(self) -> GraphData:
        source = "\n".join(self._source_lines)
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            self._graph.errors.append(
                CryptoError(
                    code="SYNTAX_ERROR",
                    severity=Severity.ERROR,
                    message=f"Syntax error in student code: {e}",
                    suggestion="Fix the syntax error before running CryptoViz.",
                )
            )
            return self._graph
        self.visit(tree)
        return self._graph

    # ── import tracking ───────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        self._resolver.record_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._resolver.record_import_from(node)
        self.generic_visit(node)

    # ── assignment: `x = some_crypto_call(...)` ───────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        rhs_node_id = self._try_extract_call(node.value, node.lineno)
        if rhs_node_id:
            for target in node.targets:
                for name in _collect_names(target):
                    self._var_to_node[name] = rhs_node_id
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            rhs_node_id = self._try_extract_call(node.value, node.lineno)
            if rhs_node_id and isinstance(node.target, ast.Name):
                self._var_to_node[node.target.id] = rhs_node_id
        self.generic_visit(node)

    # Tuple unpacking: key, iv = cipher.encrypt_and_digest(...)
    # Handled via visit_Assign already (targets can be Tuple)

    # ── standalone calls: `cipher.update(data)` without assignment ───────────

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._try_extract_call(node.value, node.lineno)
        self.generic_visit(node)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _try_extract_call(self, expr: ast.expr, lineno: int) -> Optional[str]:
        """
        If `expr` is a recognised crypto call, create a graph node and return
        its id.  Returns None if not recognised.
        """
        if not isinstance(expr, ast.Call):
            return None

        func = expr.func

        # Case 1: Name call → e.g. `os.urandom(16)` after `import os`
        #         or just `SHA256()` after `from Crypto.Hash import SHA256`
        if isinstance(func, ast.Attribute):
            obj_name, method_name = _decompose_attr(func)
            module_alias = self._resolver.module_alias(obj_name) if obj_name else ""

            # Check function patterns
            pattern = FUNCTION_PATTERNS.get((module_alias, method_name))
            if pattern is None:
                pattern = FUNCTION_PATTERNS.get((obj_name, method_name))

            if pattern:
                node_id = self._new_node_id()
                snippet = self._source_snippet(lineno)
                nd = NodeData(
                    id=node_id,
                    type=pattern.node_type,
                    label=pattern.label_template,
                    line_no=lineno,
                    col_offset=func.col_offset,
                    algorithm=pattern.algorithm,
                    source_snippet=snippet,
                )
                self._add_node(nd)
                self._wire_args(expr, nd, pattern)
                return node_id

            # Check method patterns (e.g. cipher.encrypt, hash_obj.digest)
            method_pattern = METHOD_PATTERNS.get(method_name)
            if method_pattern:
                # Handle chained calls: hashlib.md5(data).hexdigest()
                # The object (func.value) is itself a Call — process it first.
                inner_node_id: Optional[str] = None
                if isinstance(func.value, ast.Call):
                    inner_node_id = self._try_extract_call(func.value, lineno)

                node_id = self._new_node_id()
                snippet = self._source_snippet(lineno)
                nd = NodeData(
                    id=node_id,
                    type=method_pattern.node_type,
                    label=method_pattern.label_template,
                    line_no=lineno,
                    col_offset=func.col_offset,
                    source_snippet=snippet,
                )
                # Inherit algorithm from inner node when chained (e.g. md5(...).hexdigest())
                if inner_node_id and inner_node_id in self._nodes:
                    nd.algorithm = nd.algorithm or self._nodes[inner_node_id].algorithm
                self._add_node(nd)
                # Wire from inner node when chained, else from variable
                if inner_node_id:
                    self._add_edge(inner_node_id, node_id, _infer_edge_type(nd.type), "")
                elif obj_name and obj_name in self._var_to_node:
                    src = self._var_to_node[obj_name]
                    edge_type = _infer_edge_type(nd.type)
                    self._add_edge(src, node_id, edge_type, obj_name)
                # Wire args
                self._wire_args(expr, nd, method_pattern)
                return node_id

        elif isinstance(func, ast.Name):
            fn_name = func.id
            alias = self._resolver.module_alias(fn_name)

            pattern = FUNCTION_PATTERNS.get((alias, "")) or FUNCTION_PATTERNS.get((fn_name, ""))
            if pattern is None:
                # Direct constructor calls like AES(key, mode)
                pattern = FUNCTION_PATTERNS.get((alias, "new")) or FUNCTION_PATTERNS.get((fn_name, "new"))

            if pattern:
                node_id = self._new_node_id()
                nd = NodeData(
                    id=node_id,
                    type=pattern.node_type,
                    label=pattern.label_template,
                    line_no=lineno,
                    algorithm=pattern.algorithm,
                    source_snippet=self._source_snippet(lineno),
                )
                self._add_node(nd)
                self._wire_args(expr, nd, pattern)
                return node_id

        return None

    def _wire_args(self, call: ast.Call, nd: NodeData, pattern) -> None:
        """Connect variable references in call args to nd as incoming edges."""
        all_args: list[ast.expr] = list(call.args)
        for kw in call.keywords:
            if kw.value:
                all_args.append(kw.value)

        for i, arg in enumerate(all_args):
            arg_names = _collect_names_from_expr(arg)
            for name in arg_names:
                if name in self._var_to_node:
                    src = self._var_to_node[name]
                    # Determine edge label / type from pattern hints
                    if pattern.key_arg_index is not None and i == pattern.key_arg_index:
                        self._add_edge(src, nd.id, EdgeType.KEY_INPUT, "key")
                    elif pattern.data_arg_index is not None and i == pattern.data_arg_index:
                        self._add_edge(src, nd.id, EdgeType.PLAINTEXT, name)
                    elif pattern.mode_arg_index is not None and i == pattern.mode_arg_index:
                        pass  # mode is a constant attr, skip edge
                    else:
                        self._add_edge(src, nd.id, EdgeType.DATA_FLOW, name)

    def _add_node(self, nd: NodeData) -> None:
        self._nodes[nd.id] = nd
        self._graph.nodes.append(nd)

    def _add_edge(
        self,
        source: str,
        target: str,
        etype: EdgeType = EdgeType.DATA_FLOW,
        label: str = "",
    ) -> None:
        eid = f"e{self._edge_counter}"
        self._edge_counter += 1
        animated = etype in (EdgeType.KEY_INPUT, EdgeType.PLAINTEXT, EdgeType.CIPHERTEXT)
        self._graph.edges.append(
            EdgeData(id=eid, source=source, target=target, type=etype, label=label, animated=animated)
        )

    def _new_node_id(self) -> str:
        nid = f"n{self._node_counter}"
        self._node_counter += 1
        return nid

    def _source_snippet(self, lineno: int) -> str:
        start = max(0, lineno - 2)
        end = min(len(self._source_lines), lineno + 1)
        snippet = "\n".join(self._source_lines[start:end])
        return textwrap.dedent(snippet)


# ── utility helpers ───────────────────────────────────────────────────────────

def _decompose_attr(node: ast.Attribute) -> tuple[str, str]:
    """Return (object_name, attr_name) for `obj.attr`; obj may be chained."""
    method = node.attr
    value = node.value
    if isinstance(value, ast.Name):
        return value.id, method
    if isinstance(value, ast.Attribute):
        # e.g. AES.MODE_EAX → ('AES', 'MODE_EAX') — but we only need the top name
        parts: list[str] = []
        cur: ast.expr = value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return parts[0], method
    return "", method


def _collect_names(target: ast.expr) -> list[str]:
    """Return all Name ids from an assignment target (handles tuples)."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_collect_names(elt))
        return names
    return []


def _collect_names_from_expr(expr: ast.expr) -> list[str]:
    """Return variable names referenced in an expression."""
    if isinstance(expr, ast.Name):
        return [expr.id]
    if isinstance(expr, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in expr.elts:
            names.extend(_collect_names_from_expr(elt))
        return names
    return []


def _infer_edge_type(node_type: NodeType) -> EdgeType:
    if node_type in (NodeType.ENCRYPT,):
        return EdgeType.PLAINTEXT
    if node_type in (NodeType.DECRYPT,):
        return EdgeType.CIPHERTEXT
    if node_type in (NodeType.HASH, NodeType.HMAC):
        return EdgeType.HASH_INPUT
    return EdgeType.DATA_FLOW


def parse_file(filepath: str) -> GraphData:
    with open(filepath, encoding="utf-8") as f:
        source = f.read()
    parser = CryptoASTParser(source, filename=filepath)
    return parser.parse()
