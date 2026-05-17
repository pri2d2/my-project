"""Data models for the crypto visualization graph."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class NodeType(str, Enum):
    KEY_GENERATION   = "KEY_GENERATION"
    KEY_DERIVATION   = "KEY_DERIVATION"
    IV_GENERATION    = "IV_GENERATION"
    CIPHER_INIT      = "CIPHER_INIT"
    ENCRYPT          = "ENCRYPT"
    DECRYPT          = "DECRYPT"
    HASH             = "HASH"
    HMAC             = "HMAC"
    SIGN             = "SIGN"
    VERIFY           = "VERIFY"
    PADDING          = "PADDING"
    ENCODE           = "ENCODE"
    VARIABLE         = "VARIABLE"
    CONSTANT         = "CONSTANT"
    ERROR            = "ERROR"


class EdgeType(str, Enum):
    DATA_FLOW   = "DATA_FLOW"
    KEY_INPUT   = "KEY_INPUT"
    IV_INPUT    = "IV_INPUT"
    PLAINTEXT   = "PLAINTEXT"
    CIPHERTEXT  = "CIPHERTEXT"
    HASH_INPUT  = "HASH_INPUT"
    HASH_OUTPUT = "HASH_OUTPUT"
    PARAMETER   = "PARAMETER"


class Severity(str, Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


@dataclass
class CryptoError:
    code: str
    severity: Severity
    message: str
    suggestion: str


@dataclass
class NodeData:
    id: str
    type: NodeType
    label: str
    line_no: int
    col_offset: int = 0
    algorithm: Optional[str] = None
    mode: Optional[str] = None
    key_size: Optional[int] = None
    runtime_value: Optional[Any] = None
    runtime_repr: Optional[str] = None
    source_snippet: Optional[str] = None
    errors: list[CryptoError] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "lineNo": self.line_no,
            "colOffset": self.col_offset,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "keySize": self.key_size,
            "runtimeRepr": self.runtime_repr,
            "sourceSnippet": self.source_snippet,
            "errors": [
                {
                    "code": e.code,
                    "severity": e.severity.value,
                    "message": e.message,
                    "suggestion": e.suggestion,
                }
                for e in self.errors
            ],
            "metadata": self.metadata,
        }


@dataclass
class EdgeData:
    id: str
    source: str
    target: str
    type: EdgeType = EdgeType.DATA_FLOW
    label: str = ""
    animated: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "label": self.label,
            "animated": self.animated,
        }


@dataclass
class GraphData:
    nodes: list[NodeData] = field(default_factory=list)
    edges: list[EdgeData] = field(default_factory=list)
    source_file: str = ""
    errors: list[CryptoError] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "sourceFile": self.source_file,
            "errors": [
                {
                    "code": e.code,
                    "severity": e.severity.value,
                    "message": e.message,
                    "suggestion": e.suggestion,
                }
                for e in self.errors
            ],
        }
