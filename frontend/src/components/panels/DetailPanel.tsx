import type { CryptoError, GraphData, NodeData, Severity } from "../../types/graph";

const SEV_COLOR: Record<Severity, string> = {
  INFO:    "#3b82f6",
  WARNING: "#eab308",
  ERROR:   "#ef4444",
};

interface Props {
  selected: NodeData | null;
  graph: GraphData;
}

export function DetailPanel({ selected, graph }: Props) {
  const allErrors: CryptoError[] = [
    ...graph.errors,
    ...graph.nodes.flatMap((n) => n.errors),
  ];
  const errorCount = allErrors.filter((e) => e.severity === "ERROR").length;
  const warnCount  = allErrors.filter((e) => e.severity === "WARNING").length;

  return (
    <div style={panelStyle}>
      {/* Header */}
      <div style={header}>
        <span style={{ fontWeight: 700, fontSize: 15 }}>CryptoViz</span>
        <span style={{ color: "#64748b", fontSize: 11, fontFamily: "var(--mono)" }}>
          {graph.sourceFile.split("/").pop()}
        </span>
      </div>

      {/* Stats bar */}
      <div style={statsRow}>
        <Stat label="Nodes" value={graph.nodes.length} color="#6366f1" />
        <Stat label="Edges" value={graph.edges.length} color="#3b82f6" />
        <Stat label="Errors" value={errorCount} color="#ef4444" />
        <Stat label="Warns" value={warnCount} color="#eab308" />
      </div>

      <div style={divider} />

      {/* Selected node detail */}
      {selected ? (
        <NodeDetail node={selected} />
      ) : (
        <div style={hintText}>
          Click a node to see details.<br />
          Hover a node to see its runtime value.
        </div>
      )}

      <div style={divider} />

      {/* Global issues */}
      {allErrors.length > 0 && (
        <div>
          <div style={sectionTitle}>Issues</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {allErrors.map((e, i) => (
              <ErrorCard key={i} error={e} />
            ))}
          </div>
        </div>
      )}

      {allErrors.length === 0 && (
        <div style={{ ...hintText, color: "#22c55e" }}>
          No issues detected.
        </div>
      )}
    </div>
  );
}

function NodeDetail({ node }: { node: NodeData }) {
  return (
    <div>
      <div style={sectionTitle}>Selected Node</div>
      <div style={detailCard}>
        <Row label="Type"      value={node.type} mono />
        <Row label="Label"     value={node.label} />
        <Row label="Line"      value={`L${node.lineNo}`} mono />
        {node.algorithm && <Row label="Algorithm" value={node.algorithm} mono />}
        {node.mode      && <Row label="Mode"      value={node.mode} mono />}
        {node.keySize != null && <Row label="Key size" value={`${node.keySize} bits`} mono />}

        {node.runtimeRepr && (
          <div style={{ marginTop: 10 }}>
            <div style={fieldLabel}>Runtime value</div>
            <pre style={pre}>{node.runtimeRepr}</pre>
          </div>
        )}

        {node.sourceSnippet && (
          <div style={{ marginTop: 10 }}>
            <div style={fieldLabel}>Source snippet</div>
            <pre style={{ ...pre, color: "#94a3b8" }}>{node.sourceSnippet}</pre>
          </div>
        )}

        {node.errors.length > 0 && (
          <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
            {node.errors.map((e, i) => <ErrorCard key={i} error={e} />)}
          </div>
        )}
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
      <span style={fieldLabel}>{label}</span>
      <span style={{ fontSize: 12, color: "#e2e8f0", fontFamily: mono ? "var(--mono)" : undefined, textAlign: "right" }}>
        {value}
      </span>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 18, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>{label}</div>
    </div>
  );
}

function ErrorCard({ error }: { error: CryptoError }) {
  return (
    <div style={{ ...errorCard, borderColor: SEV_COLOR[error.severity] }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: SEV_COLOR[error.severity], display: "inline-block" }} />
        <span style={{ fontSize: 11, fontWeight: 600, color: SEV_COLOR[error.severity] }}>{error.severity}</span>
        <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--mono)" }}>{error.code}</span>
      </div>
      <div style={{ fontSize: 12, color: "#e2e8f0", marginBottom: 4 }}>{error.message}</div>
      {error.suggestion && error.code !== "RUNTIME_ERROR" && (
        <div style={{ fontSize: 11, color: "#94a3b8" }}>{error.suggestion}</div>
      )}
      {error.code === "RUNTIME_ERROR" && (
        <pre style={{ ...pre, color: "#ef4444", fontSize: 10, maxHeight: 200, overflowY: "auto" }}>
          {error.suggestion}
        </pre>
      )}
    </div>
  );
}

// ── styles ────────────────────────────────────────────────────────────────────

const panelStyle: React.CSSProperties = {
  width: 300,
  height: "100%",
  background: "#1a1d27",
  borderLeft: "1px solid #2e3354",
  display: "flex",
  flexDirection: "column",
  gap: 0,
  overflowY: "auto",
  padding: 16,
  flexShrink: 0,
};

const header: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 2,
  marginBottom: 12,
};

const statsRow: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-around",
  padding: "8px 0",
};

const divider: React.CSSProperties = {
  height: 1,
  background: "#2e3354",
  margin: "12px 0",
};

const sectionTitle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  color: "#64748b",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  marginBottom: 8,
};

const hintText: React.CSSProperties = {
  fontSize: 12,
  color: "#64748b",
  lineHeight: 1.6,
  textAlign: "center",
  padding: "8px 0",
};

const detailCard: React.CSSProperties = {
  background: "#22263a",
  borderRadius: 8,
  padding: "10px 12px",
  border: "1px solid #2e3354",
};

const fieldLabel: React.CSSProperties = {
  fontSize: 10,
  color: "#64748b",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};

const pre: React.CSSProperties = {
  background: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: 6,
  padding: "6px 8px",
  fontSize: 11,
  fontFamily: "var(--mono)",
  color: "#22c55e",
  whiteSpace: "pre-wrap",
  wordBreak: "break-all",
};

const errorCard: React.CSSProperties = {
  background: "#0f1117",
  border: "1px solid",
  borderRadius: 8,
  padding: "8px 10px",
};
