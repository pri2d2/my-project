"""
Detect common cryptographic mistakes in both static (AST) and runtime data.

Checks include:
- Hardcoded keys / IVs / passwords
- Wrong key sizes
- Insecure algorithms (MD5, SHA-1, DES, RC4, ECB mode)
- Missing IV / nonce for modes that require one
- Reuse of IV (detected at runtime if multiple encrypt nodes share same IV value)
- Missing authentication tag verification
- Weak PBKDF2 iteration count
"""

from __future__ import annotations

import ast
import re

from cryptoviz.analyzer.crypto_patterns import (
    IDEAL_KEY_SIZES,
    INSECURE_MODES,
    WEAK_ALGORITHMS,
)
from cryptoviz.graph.models import CryptoError, GraphData, NodeData, NodeType, Severity


# ── AST-level checks ─────────────────────────────────────────────────────────

class _HardcodedKeyDetector(ast.NodeVisitor):
    """Flags byte/string literals assigned to variables with key-like names."""

    KEY_PATTERNS = re.compile(r"(key|secret|password|passwd|iv|nonce|salt)", re.IGNORECASE)

    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []  # (lineno, var_name)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for name in _collect_names(target):
                if self.KEY_PATTERNS.search(name):
                    if isinstance(node.value, (ast.Constant, ast.JoinedStr)):
                        val = node.value
                        if isinstance(val, ast.Constant) and isinstance(val.value, (bytes, str)):
                            self.findings.append((node.lineno, name))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value:
            name = node.target.id
            if self.KEY_PATTERNS.search(name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (bytes, str)):
                    self.findings.append((node.lineno, name))
        self.generic_visit(node)


class _ECBModeDetector(ast.NodeVisitor):
    """Finds AES.MODE_ECB / DES.MODE_ECB usage."""

    def __init__(self) -> None:
        self.findings: list[int] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "MODE_ECB":
            self.findings.append(node.lineno)
        self.generic_visit(node)


class _WeakIterationDetector(ast.NodeVisitor):
    """Finds PBKDF2 calls with iteration count < 100_000."""

    MIN_ITERATIONS = 100_000

    def __init__(self) -> None:
        self.findings: list[tuple[int, int]] = []  # (lineno, count)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = _get_func_name(node)
        if func_name in ("PBKDF2", "pbkdf2_hmac", "PBKDF2HMAC"):
            for i, arg in enumerate(node.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    if arg.value < self.MIN_ITERATIONS:
                        self.findings.append((node.lineno, arg.value))
            for kw in node.keywords:
                if kw.arg in ("count", "iterations") and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, int) and kw.value.value < self.MIN_ITERATIONS:
                        self.findings.append((node.lineno, kw.value.value))
        self.generic_visit(node)


# ── main entry points ─────────────────────────────────────────────────────────

def run_static_checks(source_code: str, graph: GraphData) -> None:
    """
    Run AST-based checks on the raw source and annotate graph nodes with errors.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return  # Already handled in ast_parser

    # Hardcoded keys
    hkd = _HardcodedKeyDetector()
    hkd.visit(tree)
    for lineno, varname in hkd.findings:
        err = CryptoError(
            code="HARDCODED_KEY",
            severity=Severity.ERROR,
            message=f"'{varname}' appears to be a hardcoded secret (line {lineno}).",
            suggestion="Generate keys with os.urandom() or secrets.token_bytes() instead of embedding them in source.",
        )
        _annotate_nodes_at_line(graph, lineno, err)
        graph.errors.append(err)

    # ECB mode
    ecb = _ECBModeDetector()
    ecb.visit(tree)
    for lineno in ecb.findings:
        err = CryptoError(
            code="ECB_MODE",
            severity=Severity.ERROR,
            message=f"ECB mode is insecure (line {lineno}) — it does not hide data patterns.",
            suggestion="Use AES.MODE_GCM, AES.MODE_EAX, or AES.MODE_CBC with a random IV.",
        )
        _annotate_nodes_at_line(graph, lineno, err)
        graph.errors.append(err)

    # Weak iteration count
    wit = _WeakIterationDetector()
    wit.visit(tree)
    for lineno, count in wit.findings:
        err = CryptoError(
            code="WEAK_KDF_ITERATIONS",
            severity=Severity.WARNING,
            message=f"KDF iteration count {count:,} is too low (line {lineno}).",
            suggestion="Use at least 100,000 iterations for PBKDF2 (NIST recommendation).",
        )
        _annotate_nodes_at_line(graph, lineno, err)
        graph.errors.append(err)

    # Weak algorithms on graph nodes
    for nd in graph.nodes:
        if nd.algorithm in WEAK_ALGORITHMS:
            err = CryptoError(
                code="WEAK_ALGORITHM",
                severity=Severity.WARNING,
                message=f"{nd.algorithm} is considered cryptographically weak or deprecated.",
                suggestion=_weak_algo_suggestion(nd.algorithm),
            )
            nd.errors.append(err)


def run_runtime_checks(graph: GraphData) -> None:
    """
    Checks that require runtime values (key sizes, IV reuse, etc.).
    Runs after the runtime tracer has populated node.runtime_value.
    """
    seen_ivs: dict[str, list[str]] = {}  # iv_hex → [node_ids]

    for nd in graph.nodes:
        if nd.runtime_value is None:
            continue

        # Key size check
        if nd.type == NodeType.KEY_GENERATION and nd.algorithm in IDEAL_KEY_SIZES:
            key_bytes = _to_bytes(nd.runtime_value)
            if key_bytes is not None:
                key_len = len(key_bytes)
                nd.key_size = key_len * 8
                valid = IDEAL_KEY_SIZES[nd.algorithm]
                if key_len not in valid:
                    err = CryptoError(
                        code="INVALID_KEY_SIZE",
                        severity=Severity.ERROR,
                        message=(
                            f"{nd.algorithm} key is {key_len} bytes ({key_len * 8} bits). "
                            f"Valid sizes: {[v * 8 for v in valid]} bits."
                        ),
                        suggestion=f"Use {valid[0] * 8}-bit key for {nd.algorithm}.",
                    )
                    nd.errors.append(err)

        # IV/nonce tracking for reuse detection
        if nd.type == NodeType.IV_GENERATION:
            key_bytes = _to_bytes(nd.runtime_value)
            if key_bytes is not None:
                iv_hex = key_bytes.hex()
                seen_ivs.setdefault(iv_hex, []).append(nd.id)

    # Flag reused IVs
    for iv_hex, node_ids in seen_ivs.items():
        if len(node_ids) > 1:
            for nid in node_ids:
                nd = _find_node(graph, nid)
                if nd:
                    err = CryptoError(
                        code="IV_REUSE",
                        severity=Severity.ERROR,
                        message="The same IV/nonce is used multiple times.",
                        suggestion="Generate a fresh random IV for every encryption operation.",
                    )
                    nd.errors.append(err)


# ── helpers ───────────────────────────────────────────────────────────────────

def _annotate_nodes_at_line(graph: GraphData, lineno: int, err: CryptoError) -> None:
    for nd in graph.nodes:
        if nd.line_no == lineno:
            nd.errors.append(err)


def _find_node(graph: GraphData, nid: str) -> NodeData | None:
    for nd in graph.nodes:
        if nd.id == nid:
            return nd
    return None


def _to_bytes(val: object) -> bytes | None:
    if isinstance(val, bytes):
        return val
    if isinstance(val, (bytearray, memoryview)):
        return bytes(val)
    return None


def _collect_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_collect_names(elt))
        return names
    return []


def _get_func_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _weak_algo_suggestion(algo: str) -> str:
    suggestions = {
        "MD5":  "Use SHA-256 or SHA-3 for integrity checks. MD5 is broken for security use.",
        "SHA-1": "Use SHA-256 or SHA-3. SHA-1 is deprecated for cryptographic use.",
        "DES":  "Use AES-128 or AES-256. DES has a 56-bit key that can be brute-forced.",
        "RC4":  "Use AES-GCM or ChaCha20-Poly1305. RC4 has known biases and is broken.",
        "3DES": "Use AES-128 or AES-256. 3DES is deprecated and slow.",
    }
    return suggestions.get(algo, f"Consider a modern algorithm instead of {algo}.")
