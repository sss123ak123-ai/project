"""
Detection for error-based SQL injection indicators.
"""

from __future__ import annotations

import re
from typing import Dict, List

import requests

from core.ai_judge import FindingCandidate


ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning: pg_.*", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"ORA-\\d{5}", re.IGNORECASE),
]


class SQLErrorDetector:
    """
    Looks for database error messages that indicate injectable inputs.
    """

    def analyze(self, response: requests.Response, params: Dict[str, str]) -> List[FindingCandidate]:
        body = response.text or ""
        indicators = [pattern.pattern for pattern in ERROR_PATTERNS if pattern.search(body)]

        if not indicators:
            return []

        candidate = FindingCandidate(
            vulnerability_type="SQLi",
            indicators=indicators,
            severity_score=0.65,
            reasoning="Database error patterns observed in response; input may be unsafely concatenated.",
            recommended_next_step="Attempt parameterized queries or prepared statements; manually confirm stack trace context.",
        )
        return [candidate]
