"""Fetch and cache CloudFormation Template Reference pages as property sections.

Only pages under the Template Reference for the type's own namespace are read.
The cache stores extracted text and the SHA-256 of the fetched HTML, so review
quotes can be checked against the same text later.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .source_audit import documentation_url


BASE = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SECTION = re.compile(r'<dt id="([^"]+)">(.*?)</dt>\s*<dd>(.*?)</dd>', re.DOTALL)
INTRO = re.compile(r"<h1[^>]*>.*?</h1>(.*?)<h2", re.DOTALL)
LINK = re.compile(r'href="\./((?:aws|alexa)-properties-[a-z0-9-]+\.html)"')


def text(fragment: str) -> str:
    fragment = re.sub(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", " ", fragment, flags=re.DOTALL)
    fragment = re.sub(r"</?(?:p|br|li|ul|ol|dl|dt|dd|div|tr|td|th|table|h\d|pre|span class=\"term\")\b[^>]*>",
                      " ", fragment)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def normalize(value: str) -> str:
    return " ".join(value.split())


def _prefix(type_name: str) -> str:
    vendor, service, resource = type_name.split("::")
    return f"{'aws' if vendor == 'AWS' else 'alexa'}-properties-{service.lower()}-{resource.lower()}-"


def fetch_page(url: str, cache_dir: Path, *, timeout: int = 30) -> dict:
    """Return the cached extraction of one page, fetching it when absent."""
    name = urlparse(url).path.rsplit("/", 1)[-1]
    path = cache_dir / (name + ".json")
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    request = urllib.request.Request(url, headers={"User-Agent": "aws-design-sheet-review/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final = response.url
            if urlparse(final).hostname != "docs.aws.amazon.com":
                raise ValueError("documentation redirected outside docs.aws.amazon.com")
            raw = response.read()
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        return {"url": url, "error": str(exc), "sections": [], "links": []}
    page = raw.decode("utf-8", errors="replace")
    match = TITLE.search(page)
    intro = INTRO.search(page)
    result = {"url": url, "final_url": final,
              "fetched_at": datetime.now(timezone.utc).isoformat(),
              "html_sha256": hashlib.sha256(raw).hexdigest(),
              "title": text(match.group(1)) if match else "",
              "intro": text(intro.group(1)) if intro else "",
              "sections": [{"id": anchor, "name": text(term), "text": text(body)}
                           for anchor, term, body in SECTION.findall(page)],
              "links": sorted(set(LINK.findall(page)))}
    cache_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    return result


def type_pages(type_name: str, cache_dir: Path) -> list[dict]:
    """The resource page and the property pages it links for the same resource type."""
    first = fetch_page(documentation_url(type_name), cache_dir)
    if first.get("error") or type_name not in first.get("title", ""):
        return [first]
    prefix = _prefix(type_name)
    pages, seen, queue = [first], {first["url"]}, list(first["links"])
    while queue:
        name = queue.pop(0)
        url = BASE + name
        if url in seen or not name.startswith(prefix):
            continue
        seen.add(url)
        page = fetch_page(url, cache_dir)
        pages.append(page)
        queue.extend(page.get("links", []))
    return pages


def prefetch(type_names: list[str], cache_dir: Path, workers: int = 12) -> dict:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda name: (name, type_pages(name, cache_dir)), type_names))
    return {"types": len(results),
            "pages": sum(len(pages) for _, pages in results),
            "errors": sorted(name for name, pages in results if pages[0].get("error") or
                             name not in pages[0].get("title", ""))}


def quote_in_page(url: str, quote: str, cache_dir: Path) -> bool:
    """True when the quote appears in the cited section (or the intro) of a cached page."""
    base, _, anchor = url.partition("#")
    if not base.startswith(BASE):
        return False
    page = fetch_page(base, cache_dir)
    if page.get("error"):
        return False
    wanted = normalize(quote)
    if anchor == "intro":
        corpus = [page.get("intro", "")]
    else:
        corpus = [section["text"] for section in page["sections"] if section["id"] == anchor]
    return any(wanted in normalize(item) for item in corpus)
