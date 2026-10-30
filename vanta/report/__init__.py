"""Report generation: turn a ScanReport into a human deliverable."""

from vanta.report.markdown import render_markdown
from vanta.report.html import render_html

__all__ = ["render_markdown", "render_html"]
