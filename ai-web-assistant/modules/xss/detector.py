"""
Detection heuristics for reflected and stored XSS indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

import requests

from core.ai_judge import FindingCandidate


@dataclass
class XSSSignal:
    reflected: bool
    script_like: bool
    html_breakout: bool


class XSSDetector:
    PAYLOAD_MARKER = "aiwebassistantxss"
    PATTERNS = [
        re.compile(r"<script[^>]*>"),
        re.compile(r"onerror\\s*=\\s*"),
        re.compile(r"alert\\s*\\(\\s*['\\\"]?"),
    ]

    def _extract_signals(self, response_text: str) -> XSSSignal:
        reflected = self.PAYLOAD_MARKER in response_text
        script_like = any(pattern.search(response_text) for pattern in self.PATTERNS)
        html_breakout = "&lt;script" in response_text.lower()
        return XSSSignal(reflected=reflected, script_like=script_like, html_breakout=html_breakout)

    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        body = response.text or ""
        signals = self._extract_signals(body)

        indicators = []
        severity_score = 0.0

        if signals.reflected:
            indicators.append("Payload reflection detected")
            severity_score += 0.4
        if signals.script_like:
            indicators.append("Script-like content present near payload")
            severity_score += 0.3
        if signals.html_breakout:
            indicators.append("HTML entity breakout observed")
            severity_score += 0.2

        if not indicators:
            return []

        candidate = FindingCandidate(
            vulnerability_type="XSS",
            indicators=indicators,
            severity_score=min(severity_score, 1.0),
            reasoning="Potential XSS due to reflected payload and script-like context.",
            recommended_next_step="Manual confirmation with browser-based context and screenshot.",
        )
        return [candidate]
