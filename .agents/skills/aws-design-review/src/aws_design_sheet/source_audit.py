"""Inventory official documentation pages for every pinned resource type.

This is source discovery, not a design-rule review. It never edits the ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .ledger import validate_ledger


TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
CONDITION = re.compile(r"\b(?:if|when|must|cannot|requires?|only|either|unless|depends?)\b", re.IGNORECASE)


def documentation_url(type_name: str) -> str:
    parts = type_name.split("::")
    if len(parts) != 3 or parts[0] not in ("AWS", "Alexa"):
        raise ValueError(f"unsupported resource type: {type_name}")
    prefix = "aws" if parts[0] == "AWS" else "alexa"
    slug = "-".join(part.lower() for part in parts[1:])
    return f"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/{prefix}-resource-{slug}.html"


def inspect_page(type_name: str, *, timeout: int = 20) -> dict:
    url = documentation_url(type_name)
    request = urllib.request.Request(url, headers={"User-Agent": "aws-design-sheet-source-audit/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = response.url
            if urlparse(final_url).hostname != "docs.aws.amazon.com":
                raise ValueError("documentation redirected outside docs.aws.amazon.com")
            raw = response.read()
            status = response.status
        page = raw.decode("utf-8", errors="replace")
        match = TITLE.search(page)
        title = html.unescape(re.sub(r"\s+", " ", match.group(1)).strip()) if match else ""
        return {"url": final_url, "http_status": status, "title": title,
                "title_matches_type": type_name in title,
                "content_sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        return {"url": url, "http_status": getattr(exc, "code", None),
                "title_matches_type": False, "error": str(exc)}


def build_audit(ledger_path: Path, schema_dir: Path, *, namespace: str | None = None,
                workers: int = 8) -> dict:
    if not 1 <= workers <= 32:
        raise ValueError("workers must be between 1 and 32")
    ledger = validate_ledger(ledger_path, schema_dir)
    manifest = json.loads((schema_dir / "manifest.json").read_text(encoding="utf-8"))
    names = [name for name in sorted(manifest["types"])
             if namespace is None or name.split("::")[1] == namespace]
    if not names:
        raise ValueError(f"no resource types for namespace: {namespace}")
    rows = {}
    with zipfile.ZipFile(schema_dir / manifest["archive"]) as archive:
        for name in names:
            schema = json.loads(archive.read(manifest["types"][name]))
            rows[name] = {"ledger_state": ledger["types"][name]["state"],
                          "schema_required": schema.get("required", []),
                          "conditional_description_paths": sorted(
                              "/properties/" + key for key, definition in schema.get("properties", {}).items()
                              if CONDITION.search(definition.get("description", "")))}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(inspect_page, name): name for name in names}
        for future in as_completed(futures):
            rows[futures[future]].update(future.result())
    counts = {"verified": sum(row.get("title_matches_type", False) for row in rows.values()),
              "unverified": sum(not row.get("title_matches_type", False) for row in rows.values())}
    return {"status": "COMPLETE", "kind": "SOURCE_DISCOVERY_ONLY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_region": manifest["region"],
            "schema_zip_sha256": manifest["zip_sha256"],
            "ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
            "namespace": namespace, "counts": counts, "types": rows}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Discover official CloudFormation pages for pinned types")
    parser.add_argument("--ledger", type=Path, default=root / "rules/ledger.json")
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--namespace")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_audit(args.ledger, args.schemas, namespace=args.namespace,
                             workers=args.workers)
    except Exception as exc:
        result = {"status": "FAILED", "diagnostic": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps({"status": result["status"],
                                 "counts": result.get("counts"),
                                 "output": str(args.output)}, ensure_ascii=False) + "\n")
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
