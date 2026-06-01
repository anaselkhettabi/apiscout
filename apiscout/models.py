from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim white",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "✕",
    Severity.HIGH: "▲",
    Severity.MEDIUM: "◆",
    Severity.LOW: "◇",
    Severity.INFO: "·",
}


@dataclass
class Finding:
    id: str
    severity: Severity
    module: str
    endpoint: str
    title: str
    detail: str
    remediation: str = ""
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    spec_source: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    endpoints_discovered: list[str] = field(default_factory=list)
    endpoints_probed: int = 0
    duration_s: float = 0.0

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def count_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(raw, 100)

    def grade(self) -> str:
        score = self.risk_score()
        if score == 0:
            return "A+"
        elif score < 10:
            return "A"
        elif score < 25:
            return "B"
        elif score < 45:
            return "C"
        elif score < 65:
            return "D"
        return "F"
