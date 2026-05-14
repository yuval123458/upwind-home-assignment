"""Detects HTML links where the visible text claims one URL but href points elsewhere.

Classic phishing pattern:
    <a href="http://evilhost.ru/login">https://paypal.com/login</a>
    → user sees "paypal.com", actually navigates to evilhost.ru.

We fire only when the visible text contains a URL-like string. Anchors with
non-URL text (like "Click here") are skipped — they're not deceptive in the
text-vs-href sense.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from app.scoring.schemas import Signal

MAX_POINTS = 20
POINTS_PER_MISMATCH = 10

_URL_LIKE_PATTERN = re.compile(
    r"(?:https?://|www\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+",
    re.IGNORECASE,
)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value is not None:
                    self._current_href = value
                    self._current_text = []
                    return

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _hostname(url: str) -> str | None:
    try:
        if "://" not in url:
            url = "http://" + url
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:
        return None


def _domains_match(a: str, b: str) -> bool:
    """Treat exact match or one-is-a-subdomain-of-the-other as matching."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def compute(body_html: str | None) -> Signal | None:
    if not body_html:
        return None

    parser = _LinkExtractor()
    try:
        parser.feed(body_html)
    except Exception:
        return None

    mismatches: list[tuple[str, str]] = []  # (visible_url, href)
    for href, text in parser.links:
        if not href or not text:
            continue
        if href.startswith("mailto:") or href.startswith("#") or href.startswith("javascript:"):
            continue

        text_url_match = _URL_LIKE_PATTERN.search(text)
        if not text_url_match:
            continue  # Anchor text isn't a URL — "Click here", "Reset password", etc.
        text_url = text_url_match.group(0)
        text_host = _hostname(text_url)
        href_host = _hostname(href)
        if not text_host or not href_host:
            continue
        if _domains_match(text_host, href_host):
            continue

        mismatches.append((text_url, href))

    if not mismatches:
        return None

    points = min(MAX_POINTS, len(mismatches) * POINTS_PER_MISMATCH)
    parts = [f"text {t!r} → href {h!r}" for t, h in mismatches[:3]]
    if len(mismatches) > 3:
        parts.append(f"(+{len(mismatches) - 3} more)")

    return Signal(
        name="link_anchor_mismatch",
        points=points,
        evidence="Visible link text disagrees with destination: " + "; ".join(parts),
    )
