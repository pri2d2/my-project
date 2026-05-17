"""
Runtime instrumentation via AST transformation.

Strategy:
  1. Parse the student's source into an AST.
  2. Walk the AST and wrap the RHS of known crypto assignments with a call to
     `__cryptoviz_capture__(node_id, value)` which stores the value and returns
     it unchanged.
  3. Execute the transformed AST in a controlled namespace.
  4. After execution, populate graph nodes with captured runtime values.

This approach is surgical — it only touches lines we already identified as
crypto operations, so student code runs normally with full library semantics.
"""

from __future__ import annotations

import ast
import sys
import traceback
import importlib.util
from pathlib import Path
from typing import Any

from cryptoviz.graph.models import GraphData, NodeData


# ── value representation ──────────────────────────────────────────────────────

def _repr_value(val: Any) -> str:
    """Human-readable representation of a runtime crypto value."""
    if isinstance(val, (bytes, bytearray)):
        hex_str = val.hex()
        ascii_hint = ""
        try:
            decoded = val.decode("ascii")
            if decoded.isprintable():
                ascii_hint = f' ("{decoded}")'
        except (UnicodeDecodeError, ValueError):
            pass
        size_bits = len(val) * 8
        return f"{hex_str}{ascii_hint}  [{len(val)} bytes / {size_bits} bits]"
    if hasattr(val, "__class__"):
        cls = val.__class__.__name__
        # PyCryptodome cipher objects
        if hasattr(val, "nonce"):
            try:
                return f"<{cls}  nonce={val.nonce.hex()}>"
            except Exception:
                pass
        if hasattr(val, "key_size"):
            try:
                return f"<{cls}  key_size={val.key_size * 8} bits>"
            except Exception:
                pass
        # RSA/DSA keys
        if hasattr(val, "export_key"):
            try:
                return f"<{cls}  {val.n.bit_length()} bits>" if hasattr(val, "n") else f"<{cls}>"
            except Exception:
                pass
        # cryptography library keys
        if hasattr(val, "key_size"):
            return f"<{cls}  {val.key_size} bits>"
        return f"<{cls}>"
    return repr(val)


# ── AST transformer ───────────────────────────────────────────────────────────

class _CaptureInjector(ast.NodeTransformer):
    """
    For every Assign/AnnAssign whose RHS maps to a known graph node (by line
    number), wrap that RHS with __cryptoviz_capture__(node_id, <expr>).
    """

    def __init__(self, line_to_node: dict[int, str]) -> None:
        self._line_to_node = line_to_node

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        nid = self._line_to_node.get(node.lineno)
        if nid and isinstance(node.value, ast.Call):
            node.value = self._wrap(nid, node.value)
        self.generic_visit(node)
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        if node.value:
            nid = self._line_to_node.get(node.lineno)
            if nid and isinstance(node.value, ast.Call):
                node.value = self._wrap(nid, node.value)
        self.generic_visit(node)
        return node

    def visit_Expr(self, node: ast.Expr) -> ast.Expr:
        if isinstance(node.value, ast.Call):
            nid = self._line_to_node.get(node.lineno)
            if nid:
                node.value = self._wrap(nid, node.value)
        self.generic_visit(node)
        return node

    @staticmethod
    def _wrap(node_id: str, call_expr: ast.Call) -> ast.Call:
        return ast.Call(
            func=ast.Name(id="__cryptoviz_capture__", ctx=ast.Load()),
            args=[ast.Constant(value=node_id), call_expr],
            keywords=[],
        )


# ── executor ──────────────────────────────────────────────────────────────────

def execute_and_capture(filepath: str, graph: GraphData) -> dict[str, str]:
    """
    Instrument and run the student's file, returning a dict of node_id → repr.
    Also populates node.runtime_value and node.runtime_repr on each NodeData.
    """
    source_path = Path(filepath).resolve()
    source = source_path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source, filename=str(source_path))
    except SyntaxError:
        return {}

    # Build line → node_id map
    line_to_node: dict[int, str] = {}
    for nd in graph.nodes:
        line_to_node[nd.line_no] = nd.id

    # Inject capture wrappers
    transformer = _CaptureInjector(line_to_node)
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)

    # Compile
    code = compile(new_tree, str(source_path), "exec")

    # Storage for captured values
    captured: dict[str, Any] = {}

    def __cryptoviz_capture__(node_id: str, value: Any) -> Any:
        captured[node_id] = value
        return value

    # Build exec namespace that mirrors what the student would have
    ns: dict[str, Any] = {
        "__name__": "__main__",
        "__file__": str(source_path),
        "__cryptoviz_capture__": __cryptoviz_capture__,
    }

    # Add parent dir to sys.path so student imports resolve
    parent = str(source_path.parent)
    inserted = False
    if parent not in sys.path:
        sys.path.insert(0, parent)
        inserted = True

    try:
        exec(code, ns)  # noqa: S102
    except SystemExit:
        pass  # student code calls sys.exit() — that's fine
    except Exception:
        # Capture the traceback as a graph-level error
        tb = traceback.format_exc()
        from cryptoviz.graph.models import CryptoError, Severity
        graph.errors.append(
            CryptoError(
                code="RUNTIME_ERROR",
                severity=Severity.ERROR,
                message="Student code raised an exception during execution.",
                suggestion=tb,
            )
        )
    finally:
        if inserted:
            sys.path.remove(parent)

    # Attach captured values to graph nodes
    result: dict[str, str] = {}
    node_map: dict[str, NodeData] = {nd.id: nd for nd in graph.nodes}
    for nid, val in captured.items():
        repr_str = _repr_value(val)
        result[nid] = repr_str
        if nid in node_map:
            nd = node_map[nid]
            nd.runtime_value = val
            nd.runtime_repr = repr_str

    return result
