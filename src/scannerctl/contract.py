from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    CLEAN = "clean"
    BLOCK = "block"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass(frozen=True)
class ScanResult:
    verdict: Verdict
    backend: str = ""
    backend_version: str = ""
    config_sha256: str = ""
    duration_ms: int = 0
    bytes_scanned: int = 0
    target_id: str = ""
    rule_ids: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "1"

    def to_json(self) -> str:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        payload["rule_ids"] = list(self.rule_ids)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, value: str) -> "ScanResult":
        payload = json.loads(value)
        if not isinstance(payload, dict):
            raise ValueError("result must be an object")
        if payload.get("schema_version") != "1":
            raise ValueError("unsupported schema_version")
        try:
            verdict = Verdict(payload["verdict"])
        except (KeyError, ValueError) as exc:
            raise ValueError("unknown verdict") from exc
        allowed = {field.name for field in cls.__dataclass_fields__.values()}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"unknown result fields: {sorted(unknown)}")
        for name in ("backend", "backend_version", "target_id"):
            if name in payload and not isinstance(payload[name], str):
                raise ValueError(f"{name} must be a string")
        for name in ("duration_ms", "bytes_scanned"):
            if name in payload and (
                type(payload[name]) is not int or payload[name] < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer")
        digest = payload.get("config_sha256", "")
        if not isinstance(digest, str) or (
            digest and re.fullmatch(r"[a-f0-9]{64}", digest) is None
        ):
            raise ValueError("config_sha256 must be empty or lowercase sha256")
        rule_ids = payload.get("rule_ids", [])
        if (
            not isinstance(rule_ids, list)
            or any(not isinstance(rule_id, str) for rule_id in rule_ids)
            or len(rule_ids) != len(set(rule_ids))
        ):
            raise ValueError("rule_ids must be a unique string array")
        if verdict in (Verdict.CLEAN, Verdict.BLOCK) and (
            not payload.get("backend")
            or not payload.get("backend_version")
            or not digest
            or not payload.get("target_id")
        ):
            raise ValueError("decisive verdict requires complete runtime identity")
        if verdict is Verdict.BLOCK and not rule_ids:
            raise ValueError("block verdict requires structured rule evidence")
        payload["verdict"] = verdict
        payload["rule_ids"] = tuple(rule_ids)
        return cls(**payload)
