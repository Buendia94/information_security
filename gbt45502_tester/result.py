# -*- coding: utf-8 -*-
from __future__ import annotations
import dataclasses
from typing import Any, Dict

@dataclasses.dataclass
class TestResult:
    clause: str
    name: str
    method: str
    status: str  # PASS / FAIL / WARN / MANUAL / INFO / ERROR
    evidence: Dict[str, Any]
    suggestion: str = ""
    def asdict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)
