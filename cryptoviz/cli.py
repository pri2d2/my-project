"""
cryptoviz CLI — entry point for students.

Usage:
    cryptoviz student_code.py [--port 8765] [--no-browser]
"""

from __future__ import annotations

import argparse
import sys
import time
import threading
import webbrowser
from pathlib import Path

import uvicorn

from cryptoviz.analyzer.ast_parser import parse_file
from cryptoviz.analyzer.error_detector import run_static_checks, run_runtime_checks
from cryptoviz.runtime.tracer import execute_and_capture
from cryptoviz.server.app import app, set_graph


def _print_summary(graph) -> None:
    total_errors = sum(len(nd.errors) for nd in graph.nodes) + len(graph.errors)
    print(f"  Nodes found : {len(graph.nodes)}")
    print(f"  Edges found : {len(graph.edges)}")
    if total_errors:
        print(f"  Issues found: {total_errors}  (see visualization for details)")
    else:
        print("  No issues detected.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="cryptoviz",
        description="Visualize and debug cryptographic Python code.",
    )
    parser.add_argument("file", help="Path to the student Python file to analyze.")
    parser.add_argument("--port", type=int, default=8765, help="Port for the local web server (default: 8765).")
    parser.add_argument("--no-browser", action="store_true", help="Don't open a browser automatically.")
    parser.add_argument("--static-only", action="store_true", help="Skip running the student code (static analysis only).")
    args = parser.parse_args(argv)

    filepath = Path(args.file).resolve()
    if not filepath.exists():
        print(f"[cryptoviz] Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    if filepath.suffix != ".py":
        print(f"[cryptoviz] Warning: '{filepath.name}' doesn't look like a Python file.")

    print(f"\n[cryptoviz] Analyzing: {filepath.name}")
    print("─" * 50)

    # 1. Static analysis (AST)
    print("  [1/3] Parsing AST…")
    graph = parse_file(str(filepath))

    # 2. Static error checks
    print("  [2/3] Running static checks…")
    source = filepath.read_text(encoding="utf-8")
    run_static_checks(source, graph)

    # 3. Runtime instrumentation + execution
    if not args.static_only:
        print("  [3/3] Executing with runtime tracer…")
        execute_and_capture(str(filepath), graph)
        run_runtime_checks(graph)
    else:
        print("  [3/3] Skipped (--static-only).")

    print()
    _print_summary(graph)
    print()

    # Push graph data into the server
    set_graph(graph)

    url = f"http://localhost:{args.port}"
    print(f"[cryptoviz] Starting visualization server at {url}")
    print("            Press Ctrl+C to stop.\n")

    # Open browser after a short delay so the server is ready
    if not args.no_browser:
        def _open_browser():
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open_browser, daemon=True).start()

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
