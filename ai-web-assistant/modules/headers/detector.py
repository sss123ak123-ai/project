"""
Security headers and CORS/CSP misconfiguration detection.
"""

from __future__ import annotations

from typing import Dict, List

import requests

from core.ai_judge import FindingCandidate


REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


class HeaderSecurityDetector:
    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        indicators: List[str] = []

        for header in REQUIRED_HEADERS:
            if header not in response.headers:
                indicators.append(f"Missing security header: {header}")

        csp = response.headers.get("Content-Security-Policy", "")
        if "unsafe-inline" in csp or "*" in csp:
            indicators.append("Content-Security-Policy is overly permissive")

        cors = response.headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            indicators.append("CORS allows any origin")

        if not indicators:
            return []

        severity_score = min(0.2 * len(indicators), 0.6)
        candidate = FindingCandidate(
            vulnerability_type="Security Misconfiguration",
            indicators=indicators,
            severity_score=severity_score,
            reasoning="Security headers missing or overly permissive.",
            recommended_next_step="Harden headers and tighten CSP/CORS policies.",
        )
        return [candidate]
