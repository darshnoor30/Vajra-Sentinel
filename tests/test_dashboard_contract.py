from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path


class DashboardParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.anchor_targets: list[str] = []
        self.inline_scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "a" and (values.get("href") or "").startswith("#"):
            self.anchor_targets.append(values["href"][1:])
        if tag == "script" and not values.get("src"):
            self.inline_scripts += 1


def test_dashboard_ids_and_navigation_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1] / "app" / "web"
    html = (root / "index.html").read_text(encoding="utf-8")
    parser = DashboardParser()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids))
    assert set(parser.anchor_targets).issubset(parser.ids)
    assert parser.inline_scripts == 0


def test_javascript_references_existing_elements() -> None:
    root = Path(__file__).resolve().parents[1] / "app" / "web"
    html = (root / "index.html").read_text(encoding="utf-8")
    javascript = (root / "app.js").read_text(encoding="utf-8")
    html_ids = set(re.findall(r'id="([^"]+)"', html))
    javascript_ids = set(re.findall(r'byId\("([^"]+)"\)', javascript))
    assert javascript_ids.issubset(html_ids)
