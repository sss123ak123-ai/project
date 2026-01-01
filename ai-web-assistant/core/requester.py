"""
HTTP requester with scope checking, rate limiting, and safe defaults.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


@dataclass
class RequestContext:
    url: str
    method: str = "GET"
    params: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    payload_name: Optional[str] = None


class RateLimiter:
    """
    Simple time-based rate limiter to avoid overwhelming targets.
    """

    def __init__(self, per_minute: int):
        self.per_minute = max(per_minute, 1)
        self.timestamps: List[float] = []

    def consume(self) -> None:
        now = time.time()
        window_start = now - 60
        self.timestamps = [ts for ts in self.timestamps if ts >= window_start]
        if len(self.timestamps) >= self.per_minute:
            sleep_for = 60 - (now - self.timestamps[0])
            time.sleep(max(sleep_for, 0))
        self.timestamps.append(time.time())


class Requester:
    """
    Wraps requests to add scope enforcement, rate limiting, and safe headers.
    """

    def __init__(self, allowed_domains: List[str], rate_limit_per_minute: int):
        self.allowed_domains = allowed_domains
        self.rate_limiter = RateLimiter(rate_limit_per_minute)

    def _in_scope(self, url: str) -> bool:
        hostname = urlparse(url).hostname or ""
        return any(hostname.endswith(domain) for domain in self.allowed_domains)

    def send(self, context: RequestContext) -> Optional[requests.Response]:
        if not self._in_scope(context.url):
            return None

        self.rate_limiter.consume()

        headers = {
            "User-Agent": "AI-Web-Assistant/1.0 (Ethical Security Testing)",
            "Accept": "text/html,application/json",
        }
        if context.headers:
            headers.update(context.headers)

        try:
            response = requests.request(
                context.method,
                context.url,
                params=context.params,
                data=context.data,
                headers=headers,
                timeout=10,
                allow_redirects=True,
            )
            return response
        except requests.RequestException:
            return None
