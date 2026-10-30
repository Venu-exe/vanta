"""Same-origin crawler.

Breadth-first crawl of a target that stays on the authorised scope and collects
the input surface later modules need: URLs, parameters and forms. Redirects that
leave scope are not followed (enforced by the HTTP client), and the crawl is
depth- and page-bounded so it cannot run away on a large site.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "link") and (a.get("src") or a.get("href")):
            self.links.append(a.get("src") or a.get("href"))
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            self._current_form["inputs"].append(a.get("name", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@register
class Crawler(Module):
    name = "crawler"
    category = "crawler"
    description = "Breadth-first same-origin crawl to enumerate URLs, parameters and forms"
    phase = 38

    async def run(self, ctx: RunContext) -> list[Finding]:
        probe = await ctx.fetch()
        base = ctx.shared.get("base_url") or ctx.target.base_url
        start_url = base.rstrip("/") + "/"
        max_pages = int(self.config.get("crawl_max_pages", 25))
        max_depth = int(self.config.get("crawl_max_depth", 2))
        base_host = ctx.target.host

        seen: set[str] = set()
        params: set[str] = set()
        injectable: set[str] = set()
        forms: list[dict] = []
        queue: list[tuple[str, int]] = [(start_url, 0)]
        urls_found: set[str] = set()

        while queue and len(seen) < max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)

            resp = await ctx.http.get(url)
            if not resp.ok or "text/html" not in resp.headers.get("content-type", "text/html"):
                continue

            parser = _LinkParser()
            try:
                parser.feed(resp.text)
            except Exception:  # noqa: BLE001 - malformed HTML is fine
                pass

            for link in parser.links:
                absolute = urljoin(url, link)
                parsed = urlparse(absolute)
                if parsed.hostname != base_host:
                    continue
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                urls_found.add(clean)
                if parsed.query:
                    params.update(parse_qs(parsed.query).keys())
                    injectable.add(absolute)
                if depth < max_depth and clean not in seen:
                    queue.append((clean, depth + 1))

            forms.extend(parser.forms)

        ctx.shared["crawl"] = {
            "urls": sorted(urls_found),
            "parameters": sorted(params),
            "injectable_urls": sorted(injectable),
            "forms": forms,
        }
        ctx.log.info(
            "crawler.done",
            host=base_host,
            urls=len(urls_found),
            params=len(params),
            forms=len(forms),
        )

        if not urls_found and not forms:
            return []

        findings: list[Finding] = []
        findings.append(
            Finding(
                title=f"Attack surface map for {base_host}",
                module=self.name,
                target=base_host,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category="crawler",
                description=(
                    f"Crawled {len(seen)} page(s); discovered {len(urls_found)} URL(s), "
                    f"{len(params)} unique parameter(s) and {len(forms)} form(s)."
                ),
                metadata={
                    "urls": sorted(urls_found)[:200],
                    "parameters": sorted(params),
                    "form_count": len(forms),
                },
                evidence=[
                    Evidence(
                        kind="crawl",
                        summary=f"{len(urls_found)} URLs, params: {', '.join(sorted(params)) or 'none'}",
                    )
                ],
            )
        )

        # A form posting over GET leaks data into logs/history - classic finding.
        for form in forms:
            if form["method"] == "get" and any(
                i.lower() in ("password", "passwd", "token", "secret") for i in form["inputs"]
            ):
                findings.append(
                    Finding(
                        title=f"Sensitive form submitted via GET on {base_host}",
                        module=self.name,
                        target=base_host,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        category="crawler",
                        description=(
                            f"Form action {form['action']!r} submits sensitive fields "
                            f"({', '.join(form['inputs'])}) using GET."
                        ),
                        impact="Credentials appear in URLs, browser history, and server logs.",
                        remediation="Use POST for any form handling sensitive data.",
                        cwe="CWE-598",
                        metadata={"form": form},
                        evidence=[Evidence(kind="form", summary=str(form))],
                    )
                )
        return findings
