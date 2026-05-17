export type NodeType =
  | "KEY_GENERATION"
  | "KEY_DERIVATION"
  | "IV_GENERATION"
  | "CIPHER_INIT"
  | "ENCRYPT"
  | "DECRYPT"
  | "HASH"
  | "HMAC"
  | "SIGN"
  | "VERIFY"
  | "PADDING"
  | "ENCODE"
  | "VARIABLE"
  | "CONSTANT"
  | "ERROR";

export type Severity = "INFO" | "WARNING" | "ERROR";

export interface CryptoError {
  code: string;
  severity: Severity;
  message: string;
  suggestion: string;
}

export interface NodeData {
  id: string;
  type: NodeType;
  label: string;
  lineNo: number;
  colOffset: number;
  algorithm: string | null;
  mode: string | null;
  keySize: number | null;
  runtimeRepr: string | null;
  sourceSnippet: string | null;
  errors: CryptoError[];
  metadata: Record<string, unknown>;
}

export interface EdgeData {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  animated: boolean;
}

export interface GraphData {
  nodes: NodeData[];
  edges: EdgeData[];
  sourceFile: string;
  errors: CryptoError[];
}
