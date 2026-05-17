import { useCallback, useEffect, useState } from "react";
import type { GraphData, NodeData } from "./types/graph";
import { CryptoFlow } from "./components/CryptoFlow";
import { DetailPanel } from "./components/panels/DetailPanel";

const EMPTY_GRAPH: GraphData = {
  nodes: [],
  edges: [],
  sourceFile: "",
  errors: [],
};

export default function App() {
  const [graph, setGraph] = useState<GraphData>(EMPTY_GRAPH);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<NodeData | null>(null);

  useEffect(() => {
    fetch("/api/graph")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<GraphData>;
      })
      .then((data) => {
        setGraph(data);
        setLoading(false);
      })
      .catch((err: unknown) => {
        setError(String(err));
        setLoading(false);
      });
  }, []);

  const handleSelectNode = useCallback((nd: NodeData | null) => setSelected(nd), []);

  if (loading) {
    return (
      <div style={centered}>
        <Spinner />
        <p style={{ marginTop: 16, color: "#64748b" }}>Analyzing code…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={centered}>
        <p style={{ color: "#ef4444", fontSize: 14 }}>Failed to load graph: {error}</p>
      </div>
    );
  }

  if (graph.nodes.length === 0) {
    return (
      <div style={centered}>
        <div style={{ maxWidth: 420, textAlign: "center" }}>
          <div style={{ fontSize: 40, marginBottom: 16 }}>🔍</div>
          <h2 style={{ marginBottom: 8, color: "#e2e8f0" }}>No crypto operations found</h2>
          <p style={{ color: "#64748b", lineHeight: 1.6 }}>
            CryptoViz didn't detect any recognised cryptographic operations in the
            student's code. Make sure the file imports a supported library
            (pycryptodome, cryptography, hashlib, hmac).
          </p>
          {graph.errors.length > 0 && (
            <div style={errorBox}>
              {graph.errors.map((e, i) => (
                <div key={i} style={{ marginTop: 8, color: "#ef4444", fontSize: 12 }}>
                  {e.message}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={layout}>
      {/* Legend bar */}
      <div style={legendBar}>
        <span style={logo}>CryptoViz</span>
        <span style={filename}>{graph.sourceFile.split("/").pop()}</span>
        <div style={legendItems}>
          <LegendItem color="#22c55e" label="Key" />
          <LegendItem color="#3b82f6" label="Cipher" />
          <LegendItem color="#a855f7" label="Encrypt" />
          <LegendItem color="#f97316" label="Decrypt" />
          <LegendItem color="#14b8a6" label="Hash" />
          <LegendItem color="#ec4899" label="HMAC" />
          <LegendItem color="#ef4444" label="Error" />
        </div>
      </div>

      {/* Graph canvas */}
      <div style={canvasContainer}>
        <CryptoFlow graph={graph} onSelectNode={handleSelectNode} />
      </div>

      {/* Right panel */}
      <DetailPanel selected={selected} graph={graph} />
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
      <div style={{ width: 10, height: 10, borderRadius: 3, background: color }} />
      <span style={{ fontSize: 11, color: "#94a3b8" }}>{label}</span>
    </div>
  );
}

function Spinner() {
  return (
    <div style={{
      width: 36, height: 36,
      borderRadius: "50%",
      border: "3px solid #2e3354",
      borderTop: "3px solid #6366f1",
      animation: "spin 0.8s linear infinite",
    }} />
  );
}

// ── styles ────────────────────────────────────────────────────────────────────

const layout: React.CSSProperties = {
  display: "flex",
  flexDirection: "row",
  height: "100%",
  width: "100%",
  position: "relative",
};

const canvasContainer: React.CSSProperties = {
  flex: 1,
  height: "100%",
  position: "relative",
};

const legendBar: React.CSSProperties = {
  position: "absolute",
  top: 0,
  left: 0,
  right: 300,
  height: 44,
  background: "#1a1d27cc",
  backdropFilter: "blur(8px)",
  borderBottom: "1px solid #2e3354",
  display: "flex",
  alignItems: "center",
  padding: "0 16px",
  gap: 16,
  zIndex: 10,
};

const logo: React.CSSProperties = {
  fontWeight: 700,
  fontSize: 14,
  color: "#6366f1",
  letterSpacing: "0.03em",
};

const filename: React.CSSProperties = {
  fontSize: 12,
  color: "#64748b",
  fontFamily: "var(--mono)",
  marginRight: "auto",
};

const legendItems: React.CSSProperties = {
  display: "flex",
  gap: 12,
  alignItems: "center",
};

const centered: React.CSSProperties = {
  width: "100%",
  height: "100%",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
};

const errorBox: React.CSSProperties = {
  marginTop: 16,
  padding: 12,
  background: "#450a0a44",
  border: "1px solid #ef444444",
  borderRadius: 8,
};
