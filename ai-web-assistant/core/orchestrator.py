"""
Coordinates payload generation, HTTP requests, and AI judgement.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import yaml

from core.ai_judge import AIJudge, FindingCandidate
from core.input_discovery import InputDiscovery
from core.logger import setup_logger
from core.requester import RequestContext, Requester
from modules.headers.detector import HeaderSecurityDetector
from modules.info_disclosure.detector import InfoDisclosureDetector
from modules.open_redirect.detector import OpenRedirectDetector
from modules.sqli_error.detector import SQLErrorDetector
from modules.ssti.detector import SSTIDetector
from modules.xss.detector import XSSDetector


class Orchestrator:
    """
    High-level controller that runs detectors and produces report JSON.
    """

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.logger = setup_logger(self.config.get("log_dir", "logs"))
        self.requester = Requester(
            allowed_domains=self.config.get("allowed_domains", []),
            rate_limit_per_minute=self.config.get("rate_limit_per_minute", 30),
        )
        self.judge = AIJudge()
        self.detectors = {
            "xss": XSSDetector(),
            "sqli_error": SQLErrorDetector(),
            "ssti": SSTIDetector(),
            "open_redirect": OpenRedirectDetector(),
            "info_disclosure": InfoDisclosureDetector(),
            "headers": HeaderSecurityDetector(),
        }
        self.input_discovery = InputDiscovery(self.config.get("payloads", {}))
        self.report_dir = Path(self.config.get("report_dir", "reports"))
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self, path: str) -> Dict:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def run(self) -> List[str]:
        targets = self.config.get("targets", [])
        candidates: List[FindingCandidate] = []
        variations = self.input_discovery.generate(targets)

        for module_name, url, params in variations:
            detector = self.detectors.get(module_name)
            if not detector:
                continue
            context = RequestContext(url=url, method="GET", params=params, payload_name=module_name)
            response = self.requester.send(context)
            if response is None:
                self.logger.warning("Request skipped or failed for %s", url)
                continue

            findings = detector.analyze(response, params)
            if not findings:
                continue
            candidates.extend(findings)

            if any(candidate.severity_score >= self.judge.HIGH_THRESHOLD for candidate in findings):
                self.logger.info("High confidence finding detected; stopping early for safety.")
                break

        serialized = [self.judge.evaluate(candidate) for candidate in candidates]
        self._write_report(serialized)
        return serialized

    def _write_report(self, serialized: List[str]) -> None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"report_{timestamp}.json"
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump([json.loads(item) for item in serialized], handle, indent=2)
        self.logger.info("Report written to %s", report_path)
