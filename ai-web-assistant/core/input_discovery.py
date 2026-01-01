"""
Lightweight input discovery to prepare safe payload injections.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse


class InputDiscovery:
    """
    Parses URLs and prepares variations with safe payloads for analysis.
    """

    def __init__(self, payloads: Dict[str, List[str]]):
        self.payloads = payloads

    def _mutate_query(self, url: str, payload: str) -> Tuple[str, Dict[str, str]]:
        parsed = urlparse(url)
        query_params = dict(parse_qsl(parsed.query))
        if not query_params:
            query_params = {"q": payload}
        else:
            for key in query_params:
                query_params[key] = payload
        new_query = urlencode(query_params)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed), query_params

    def generate(self, base_urls: Iterable[str]) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        For each base URL, generate mutated URLs for every module payload.

        Returns:
            List of tuples (module_name, mutated_url, params)
        """
        variations: List[Tuple[str, str, Dict[str, str]]] = []
        for module_name, payload_list in self.payloads.items():
            for base_url in base_urls:
                for payload in payload_list:
                    mutated_url, params = self._mutate_query(base_url, payload)
                    variations.append((module_name, mutated_url, params))
        return variations
