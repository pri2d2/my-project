import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { useState } from "react";
import type { NodeData, NodeType, Severity } from "../../types/graph";

// ── node type definition ──────────────────────────────────────────────────────

export type CryptoNodeData = {
  nodeData: NodeData;
  onSelect: (nd: NodeData) => void;
};
export type CryptoNodeType = Node<CryptoNodeData, "cryptoNode">;

// ── color palette per node type ───────────────────────────────────────────────

const NODE_COLORS: Record<NodeType, { bg: string; border: string; icon: string }> = {
  KEY_GENERATION: { bg: "#14532d", border: "#22c55e", icon: "🔑" },
  KEY_DERIVATION: { bg: "#14532d", border: "#86efac", icon: "🔐" },
  IV_GENERATION:  { bg: "#164e63", border: "#22d3ee", icon: "🎲" },
  CIPHER_INIT:    { bg: "#1e3a5f", border: "#3b82f6", icon: "⚙️" },
  ENCRYPT:        { bg: "#3b0764", border: "#a855f7", icon: "🔒" },
  DECRYPT:        { bg: "#431407", border: "#f97316", icon: "🔓" },
  HASH:           { bg: "#134e4a", border: "#14b8a6", icon: "#" },
  HMAC:           { bg: "#500724", border: "#ec4899", icon: "🔏" },
  SIGN:           { bg: "#1e3a5f", border: "#60a5fa", icon: "✍️" },
  VERIFY:         { bg: "#14532d", border: "#4ade80", icon: "✅" },
  PADDING:        { bg: "#27272a", border: "#71717a", icon: "⬜" },
  ENCODE:         { bg: "#27272a", border: "#a1a1aa", icon: "📦" },
  VARIABLE:       { bg: "#1c1f2e", border: "#4b5563", icon: "📌" },
  CONSTANT:       { bg: "#1c1f2e", border: "#374151", icon: "📎" },
  ERROR:          { bg: "#450a0a", border: "#ef4444", icon: "❌" },
};

const SEVERITY_COLOR: Record<Severity, string> = {
  INFO:    "#3b82f6",
  WARNING: "#eab308",
  ERROR:   "#ef4444",
};

// ── tooltip ───────────────────────────────────────────────────────────────────

function Tooltip({ data }: { data: NodeData }) {
  return (
    <div style={tooltipStyle}>
      <div style={tooltipHeader}>
        <span style={{ fontWeight: 700, fontSize: 13 }}>{data.label}</span>
        <span style={{ color: "#94a3b8", fontSize: 11 }}>Line {data.lineNo}</span>
      </div>

      {data.algorithm && (
        <div style={infoRow}>
          <span style={infoLabel}>Algorithm</span>
          <span style={infoValue}>{data.algorithm}</span>
        </div>
      )}

      {data.mode && (
        <div style={infoRow}>
          <span style={infoLabel}>Mode</span>
          <span style={infoValue}>{data.mode}</span>
        </div>
      )}

      {data.keySize != null && (
        <div style={infoRow}>
          <span style={infoLabel}>Key size</span>
          <span style={infoValue}>{data.keySize} bits</span>
        </div>
      )}

      {data.runtimeRepr && (
        <div style={{ marginTop: 8 }}>
          <div style={{ ...infoLabel, marginBottom: 4 }}>Runtime value</div>
          <pre style={runtimePre}>{data.runtimeRepr}</pre>
        </div>
      )}

      {data.sourceSnippet && (
        <div style={{ marginTop: 8 }}>
          <div style={{ ...infoLabel, marginBottom: 4 }}>Source</div>
          <pre style={{ ...runtimePre, color: "#94a3b8" }}>{data.sourceSnippet}</pre>
        </div>
      )}

      {data.errors.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {data.errors.map((err, i) => (
            <div key={i} style={{ ...errorBadge, borderColor: SEVERITY_COLOR[err.severity] }}>
              <span style={{ color: SEVERITY_COLOR[err.severity], fontWeight: 600, fontSize: 11 }}>
                {err.severity}
              </span>
              <span style={{ marginLeft: 6, fontSize: 12 }}>{err.message}</span>
              <div style={{ marginTop: 4, color: "#94a3b8", fontSize: 11 }}>
                {err.suggestion}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── main node ─────────────────────────────────────────────────────────────────

export function CryptoNode({ data, selected }: NodeProps<CryptoNodeType>) {
  const [hovered, setHovered] = useState(false);
  const nd = data.nodeData;
  const colors = NODE_COLORS[nd.type] ?? NODE_COLORS.VARIABLE;

  const hasErrors = nd.errors.length > 0;
  const maxSeverity: Severity | null = hasErrors
    ? nd.errors.reduce<Severity>((acc, e) => {
        if (e.severity === "ERROR") return "ERROR";
        if (e.severity === "WARNING" && acc !== "ERROR") return "WARNING";
        return acc;
      }, "INFO")
    : null;

  const borderColor = maxSeverity
    ? SEVERITY_COLOR[maxSeverity]
    : selected
    ? "#6366f1"
    : hovered
    ? "#c7d2fe"
    : colors.border;

  return (
    <div
      style={{
        ...nodeContainer,
        background: colors.bg,
        borderColor,
        boxShadow: hovered || selected
          ? `0 0 0 2px ${borderColor}44, 0 8px 24px #0008`
          : "0 2px 8px #0006",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={() => data.onSelect(nd)}
    >
      <Handle type="target" position={Position.Top} style={handleStyle} />

      <div style={nodeHeader}>
        <span style={{ fontSize: 16 }}>{colors.icon}</span>
        <span style={{ fontWeight: 600, fontSize: 12, color: "#e2e8f0" }}>{nd.label}</span>
        {hasErrors && (
          <span style={{ ...errorDot, background: SEVERITY_COLOR[maxSeverity!] }} />
        )}
      </div>

      {nd.algorithm && (
        <div style={algoBadge}>{nd.algorithm}</div>
      )}

      <div style={lineTag}>L{nd.lineNo}</div>

      {(hovered || selected) && <Tooltip data={nd} />}

      <Handle type="source" position={Position.Bottom} style={handleStyle} />
    </div>
  );
}

// ── styles ────────────────────────────────────────────────────────────────────

const nodeContainer: React.CSSProperties = {
  position: "relative",
  minWidth: 140,
  maxWidth: 200,
  padding: "10px 14px",
  borderRadius: 10,
  border: "1.5px solid",
  cursor: "pointer",
  transition: "border-color 0.15s, box-shadow 0.15s",
  userSelect: "none",
};

const nodeHeader: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 6,
};

const algoBadge: React.CSSProperties = {
  marginTop: 4,
  display: "inline-block",
  padding: "1px 6px",
  borderRadius: 4,
  background: "#ffffff18",
  fontSize: 10,
  color: "#94a3b8",
  fontFamily: "var(--mono)",
};

const lineTag: React.CSSProperties = {
  position: "absolute",
  top: 6,
  right: 8,
  fontSize: 10,
  color: "#64748b",
  fontFamily: "var(--mono)",
};

const errorDot: React.CSSProperties = {
  width: 8,
  height: 8,
  borderRadius: "50%",
  display: "inline-block",
  marginLeft: "auto",
};

const handleStyle: React.CSSProperties = {
  width: 8,
  height: 8,
  background: "#475569",
  border: "1.5px solid #64748b",
};

const tooltipStyle: React.CSSProperties = {
  position: "absolute",
  top: "calc(100% + 10px)",
  left: "50%",
  transform: "translateX(-50%)",
  zIndex: 9999,
  minWidth: 280,
  maxWidth: 420,
  background: "#0f1117ee",
  backdropFilter: "blur(8px)",
  border: "1px solid #2e3354",
  borderRadius: 10,
  padding: "12px 14px",
  boxShadow: "0 8px 32px #000a",
  pointerEvents: "none",
};

const tooltipHeader: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: 8,
  paddingBottom: 8,
  borderBottom: "1px solid #2e3354",
};

const infoRow: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  marginTop: 4,
  gap: 8,
};

const infoLabel: React.CSSProperties = {
  color: "#64748b",
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};

const infoValue: React.CSSProperties = {
  color: "#e2e8f0",
  fontSize: 12,
  fontFamily: "var(--mono)",
};

const runtimePre: React.CSSProperties = {
  background: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: 6,
  padding: "6px 8px",
  fontSize: 11,
  fontFamily: "var(--mono)",
  color: "#22c55e",
  whiteSpace: "pre-wrap",
  wordBreak: "break-all",
  maxHeight: 120,
  overflowY: "auto",
};

const errorBadge: React.CSSProperties = {
  marginTop: 6,
  padding: "6px 8px",
  borderRadius: 6,
  border: "1px solid",
  background: "#ffffff08",
};
