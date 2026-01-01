"""
Open Redirect detection via response location and reflection checks.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

import requests

from core.ai_judge import FindingCandidate


class OpenRedirectDetector:
    SAFE_MARKER = "https://example.com/aiwebassistant-safe"

    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        indicators: List[str] = []
        severity_score = 0.0

        location = response.headers.get("Location", "")
        if location and self.SAFE_MARKER in location:
            indicators.append("User-controlled redirect location observed")
            severity_score += 0.6

        parsed = urlparse(location)
        if parsed.netloc and parsed.scheme:
            indicators.append("External redirect target present")
            severity_score += 0.2

        if not indicators:
            return []

        candidate = FindingCandidate(
            vulnerability_type="Open Redirect",
            indicators=indicators,
            severity_score=min(severity_score, 1.0),
            reasoning="Redirect location accepts untrusted input and points externally.",
            recommended_next_step="Confirm redirect allowlist enforcement and user confirmation prompts.",
        )
        return [candidate]
