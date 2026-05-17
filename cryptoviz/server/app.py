"""FastAPI server that serves the React frontend and the graph JSON API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cryptoviz.graph.models import GraphData

# Path to the bundled React app
_STATIC_DIR = Path(__file__).parent.parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"

app = FastAPI(title="CryptoViz", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Graph data is injected before the server starts
_graph_data: dict[str, Any] = {}


def set_graph(graph: GraphData) -> None:
    global _graph_data
    _graph_data = graph.to_dict()


@app.get("/api/graph")
def get_graph() -> JSONResponse:
    return JSONResponse(_graph_data)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


# Serve the React app for all non-API routes
if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}", response_model=None)
    def serve_spa(full_path: str) -> FileResponse | HTMLResponse:
        candidate = _STATIC_DIR / full_path
        if candidate.exists() and candidate.is_file():
            return FileResponse(str(candidate))
        if _INDEX_HTML.exists():
            return FileResponse(str(_INDEX_HTML))
        return HTMLResponse("<h1>Frontend not built yet.</h1><p>Run <code>cd frontend && npm run build</code></p>", status_code=200)

else:
    @app.get("/{full_path:path}", response_model=None)
    def serve_placeholder(full_path: str) -> HTMLResponse:
        return HTMLResponse(
            "<h1>CryptoViz — Frontend not built.</h1>"
            "<p>Run <code>cd frontend && npm run build</code> then reinstall the package.</p>",
            status_code=200,
        )
