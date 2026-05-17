import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  type Node,
  type Edge,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect } from "react";
import type { GraphData, NodeData } from "../types/graph";
import { CryptoNode, type CryptoNodeData, type CryptoNodeType } from "./nodes/CryptoNode";

const nodeTypes: NodeTypes = { cryptoNode: CryptoNode as NodeTypes[string] };

// ── main component ────────────────────────────────────────────────────────────

interface Props {
  graph: GraphData;
  onSelectNode: (nd: NodeData | null) => void;
}

export function CryptoFlow({ graph, onSelectNode }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState<CryptoNodeType>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const handleSelect = useCallback(
    (nd: NodeData) => onSelectNode(nd),
    [onSelectNode]
  );

  useEffect(() => {
    // Topological sort → layered layout
    const inDegree: Record<string, number> = {};
    const children: Record<string, string[]> = {};

    for (const n of graph.nodes) {
      inDegree[n.id] = 0;
      children[n.id] = [];
    }
    for (const e of graph.edges) {
      if (!children[e.source]) children[e.source] = [];
      children[e.source].push(e.target);
      inDegree[e.target] = (inDegree[e.target] ?? 0) + 1;
    }

    const layers: string[][] = [];
    let queue = graph.nodes.filter((n) => inDegree[n.id] === 0).map((n) => n.id);
    const visited = new Set<string>();

    while (queue.length > 0) {
      layers.push([...queue]);
      queue.forEach((id) => visited.add(id));
      const next: string[] = [];
      for (const id of queue) {
        for (const child of children[id] ?? []) {
          inDegree[child]--;
          if (inDegree[child] === 0 && !visited.has(child)) next.push(child);
        }
      }
      queue = next;
    }

    const NODE_W = 180;
    const NODE_H = 80;
    const GAP_X = 60;
    const GAP_Y = 110;
    const positions: Record<string, { x: number; y: number }> = {};

    layers.forEach((layer, li) => {
      const totalWidth = layer.length * NODE_W + (layer.length - 1) * GAP_X;
      const startX = -totalWidth / 2;
      layer.forEach((id, i) => {
        positions[id] = {
          x: startX + i * (NODE_W + GAP_X),
          y: li * (NODE_H + GAP_Y),
        };
      });
    });

    // Fallback positions for disconnected / cycle nodes
    let orphanY = (layers.length + 1) * (NODE_H + GAP_Y);
    for (const n of graph.nodes) {
      if (!positions[n.id]) {
        positions[n.id] = { x: 0, y: orphanY };
        orphanY += NODE_H + GAP_Y;
      }
    }

    const rfNodes: Node<CryptoNodeData>[] = graph.nodes.map((n) => ({
      id: n.id,
      type: "cryptoNode" as const,
      position: positions[n.id] ?? { x: 0, y: 0 },
      data: { nodeData: n, onSelect: handleSelect } as CryptoNodeData,
    }));

    const EDGE_COLORS: Record<string, string> = {
      KEY_INPUT:   "#22c55e",
      IV_INPUT:    "#22d3ee",
      PLAINTEXT:   "#a855f7",
      CIPHERTEXT:  "#f97316",
      HASH_INPUT:  "#14b8a6",
      HASH_OUTPUT: "#14b8a6",
      DATA_FLOW:   "#475569",
      PARAMETER:   "#64748b",
    };

    const rfEdges: Edge[] = graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label || undefined,
      animated: e.animated,
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_COLORS[e.type] ?? "#475569" },
      style: { stroke: EDGE_COLORS[e.type] ?? "#475569", strokeWidth: 2 },
      labelStyle: { fontSize: 10, fill: "#94a3b8", fontFamily: "var(--mono)" },
      labelBgStyle: { fill: "#0f1117cc" },
    }));

    setNodes(rfNodes as CryptoNodeType[]);
    setEdges(rfEdges);
  }, [graph, handleSelect, setNodes, setEdges]);

  const onPaneClick = useCallback(() => onSelectNode(null), [onSelectNode]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.2}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
    >
      <Background color="#2e3354" gap={24} size={1} />
      <Controls />
      <MiniMap
        nodeColor={(n) => {
          const nodeData = n.data as CryptoNodeData | undefined;
          const nd = nodeData?.nodeData;
          if (!nd) return "#2e3354";
          if (nd.errors.some((e) => e.severity === "ERROR")) return "#ef4444";
          if (nd.errors.some((e) => e.severity === "WARNING")) return "#eab308";
          return "#6366f1";
        }}
        maskColor="#0f111788"
      />
    </ReactFlow>
  );
}
