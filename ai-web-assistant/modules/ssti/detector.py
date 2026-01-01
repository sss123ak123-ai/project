"""
Server-Side Template Injection detection via execution indicators only.
"""

from __future__ import annotations

import re
from typing import Dict, List

import requests

from core.ai_judge import FindingCandidate


class SSTIDetector:
    EXECUTION_MARKER = "aiwebassistant_ssti"
    TEMPLATING_PATTERNS = [
        re.compile(r"\\{\\{\\s*aiwebassistant_ssti\\s*\\}\\}", re.IGNORECASE),
        re.compile(r"\\$\\{\\s*aiwebassistant_ssti\\s*\\}", re.IGNORECASE),
        re.compile(r"\\*\\s*aiwebassistant_ssti\\s*\\*", re.IGNORECASE),
    ]

    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        body = response.text or ""
        indicators = []
        severity_score = 0.0

        if self.EXECUTION_MARKER in body:
            indicators.append("Raw marker rendered in template output")
            severity_score += 0.45
        if any(pattern.search(body) for pattern in self.TEMPLATING_PATTERNS):
            indicators.append("Template expression echoed verbatim")
            severity_score += 0.25
        if response.status_code >= 500:
            indicators.append("Server error during template rendering")
            severity_score += 0.15

        if not indicators:
            return []

        candidate = FindingCandidate(
            vulnerability_type="SSTI",
            indicators=indicators,
            severity_score=min(severity_score, 1.0),
            reasoning="Template markers echoed or executed, indicating possible SSTI.",
            recommended_next_step="Manually validate template context and confirm execution boundaries.",
        )
        return [candidate]
