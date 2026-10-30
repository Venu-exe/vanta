"""Shared helpers for the vulnerability modules.

Centralises the question "which URL/parameter pairs should I test?" so the SQLi,
XSS and SSRF modules reuse exactly the same attack surface the crawler mapped.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse


def candidate_urls(ctx) -> list[str]:
    """Ordered, de-duplicated list of URLs worth injecting into."""
    urls: list[str] = []

    # An explicitly supplied target URL with a query string wins.
    if urlparse(ctx.target.url).query:
        urls.append(ctx.target.url)

    crawl = ctx.shared.get("crawl", {})
    urls.extend(crawl.get("injectable_urls", []))

    if not urls:
        urls.append(ctx.base_url.rstrip("/") + "/")

    seen: set[str] = set()
    ordered: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def injection_points(ctx, max_urls: int = 6, max_params: int = 8) -> list[tuple[str, str]]:
    """Return ``(url, parameter)`` pairs to probe."""
    crawl_params = list(ctx.shared.get("crawl", {}).get("parameters", []))
    points: list[tuple[str, str]] = []
    for url in candidate_urls(ctx)[:max_urls]:
        params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        if not params:
            params = crawl_params
        for param in params[:max_params]:
            points.append((url, param))
    return points
