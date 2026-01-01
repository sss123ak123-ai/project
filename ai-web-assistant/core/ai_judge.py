"""
AI decisioning engine for interpreting detection signals and emitting structured JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import List


@dataclass
class FindingCandidate:
    """
    Representation of a potential vulnerability before AI judgement.
    """

    vulnerability_type: str
    indicators: List[str]
    severity_score: float  # 0.0 - 1.0
    reasoning: str
    recommended_next_step: str


class AIJudge:
    """
    Applies conservative heuristics to reduce false positives and emit structured JSON decisions.
    """

    HIGH_THRESHOLD = 0.75
    MEDIUM_THRESHOLD = 0.45

    def evaluate(self, candidate: FindingCandidate) -> str:
        """
        Convert a candidate into a strict JSON verdict.

        Args:
            candidate: FindingCandidate containing signals from a detection module.

        Returns:
            JSON string conforming to the required output schema.
        """
        severity = candidate.severity_score
        if severity >= self.HIGH_THRESHOLD and len(candidate.indicators) >= 2:
            is_vulnerable, confidence = True, "high"
        elif severity >= self.MEDIUM_THRESHOLD:
            is_vulnerable, confidence = True, "medium"
        else:
            is_vulnerable, confidence = False, "low"

        result = {
            "is_vulnerable": is_vulnerable,
            "vulnerability_type": candidate.vulnerability_type,
            "confidence": confidence,
            "reason": candidate.reasoning,
            "recommended_next_step": candidate.recommended_next_step,
        }
        return json.dumps(result, ensure_ascii=False)


def summarize_findings(candidates: List[FindingCandidate]) -> List[str]:
    """
    Helper to evaluate and serialize multiple candidates.
    """
    judge = AIJudge()
    return [judge.evaluate(candidate) for candidate in candidates]
