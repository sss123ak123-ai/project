"""
Sensitive information disclosure detection for server banners and secrets.
"""

from __future__ import annotations

import re
from typing import Dict, List

import requests

from core.ai_judge import FindingCandidate


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(r"(?i)password\\s*="),
    re.compile(r"PRIVATE KEY----"),
    re.compile(r"mongodb://", re.IGNORECASE),
]


class InfoDisclosureDetector:
    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        indicators: List[str] = []
        severity_score = 0.0

        server_header = response.headers.get("Server")
        if server_header:
            indicators.append(f"Server header exposed: {server_header}")
            severity_score += 0.15

        body = response.text or ""
        for pattern in SECRET_PATTERNS:
            if pattern.search(body):
                indicators.append(f"Potential secret pattern: {pattern.pattern}")
                severity_score += 0.5

        if "stack trace" in body.lower() or "traceback" in body.lower():
            indicators.append("Stack trace disclosed")
            severity_score += 0.25

        if not indicators:
            return []

        candidate = FindingCandidate(
            vulnerability_type="Information Disclosure",
            indicators=indicators,
            severity_score=min(severity_score, 1.0),
            reasoning="Response leaks server metadata or potential secrets.",
            recommended_next_step="Scrub sensitive data and enable generic error handling.",
        )
        return [candidate]
