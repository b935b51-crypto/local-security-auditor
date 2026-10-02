"""Presentation-only coverage groups derived from the public component view."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CoverageLayer:
    key: str
    label: str
    label_zh: str
    status: str
    explanation: str
    explanation_zh: str
    reasons: tuple[str, ...]


_GROUPS = (
    ("SOURCE", "Source & deterministic analysis", "原始碼與確定性分析",
     ("discovery", "secrets", "sast.python", "behavior.static")),
    ("DEPENDENCY", "Dependency vulnerability intelligence", "依賴漏洞情報", ("dependencies",)),
    ("CORRELATION", "Correlation / attack-path / risk enrichment", "關聯、攻擊路徑與風險補強", ("correlation",)),
)
_ORDER = ("FAILED", "ABORTED", "PARTIAL", "DISABLED", "COMPLETE")


def coverage_layers(coverage: dict, *, report_truncated: bool = False) -> tuple[CoverageLayer, ...]:
    """Never alter component/overall status or Gate; missing/disabled is not complete."""
    layers = []
    inventory_limited = report_truncated or bool(set(coverage.get("reasons", ())) & {
        "REPORT_TRUNCATED", "REPORT_FINGERPRINT_COLLISION", "RULE_CATALOG_CONFLICT"})
    for key, label, label_zh, names in _GROUPS:
        components = [item for item in coverage["components"] if item["component"] in names]
        states = [item["status"] for item in components]
        if any(not any(item["component"] == name for item in components) for name in names):
            states.append("DISABLED")
        status = next((state for state in _ORDER if state in states), "DISABLED")
        reasons = tuple(sorted({reason for item in components for reason in item["reasons"]}))
        if key == "SOURCE":
            if status == "COMPLETE" and not inventory_limited:
                en = "Source-code finding inventory from enabled and supported deterministic analyzers is complete."
                zh = "目前已啟用且受支援的原始碼確定性分析器，其 Finding 清單已完整產生。"
            elif status == "COMPLETE":
                en = "Source analyzers completed, but report truncation or identity conflicts prevent a complete public finding inventory claim."
                zh = "原始碼分析器已完成，但報告截斷或身分衝突使公開 Finding 清單無法宣稱完整。"
            else:
                en = "Source analysis is incomplete or not fully enabled; source finding inventory completeness is not established."
                zh = "原始碼分析不完整或未完整啟用，無法宣稱其 Finding 清單已完整產生。"
        elif key == "DEPENDENCY":
            if status == "COMPLETE":
                en = "Dependency vulnerability intelligence is complete within analyzed coverage; this does not prove exploitability or absence of vulnerabilities."
                zh = "已分析範圍內的依賴漏洞情報完整；這不證明可利用性，也不證明沒有漏洞。"
            else:
                en = "Dependency vulnerability intelligence is incomplete or disabled."
                zh = "依賴漏洞情報不完整或未啟用。"
        else:
            if status == "COMPLETE":
                en = "Correlation enrichment completed within analyzed coverage; attack paths are hypotheses, not proof of exploitability."
                zh = "已分析範圍內的關聯補強已完成；攻擊路徑是假設，不是可利用性的證明。"
            else:
                en = "Correlation, attack-path, or risk-priority enrichment may be incomplete. Upstream incomplete coverage also propagates to this layer."
                zh = "Finding 關聯、攻擊路徑或風險優先級補強可能不完整；上游覆蓋不完整也會傳播至此層。"
        layers.append(CoverageLayer(key, label, label_zh, status, en, zh, reasons))
    return tuple(layers)
