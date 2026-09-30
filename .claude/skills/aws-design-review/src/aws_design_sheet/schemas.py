"""Download and pin a regional CloudFormation resource schema archive."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .schema_diff import reconcile


def update(region: str, destination: Path, rules_dir: Path | None = None) -> dict:
    """Pin a new archive; with rules_dir, carry the review ledger across the change."""
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d+", region):
        raise ValueError("invalid AWS region")
    url = f"https://schema.cloudformation.{region}.amazonaws.com/CloudformationSchema.zip"
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = response.read()
    return pin(archive, url, region, destination, rules_dir)


def pin(archive: bytes, url: str, region: str, destination: Path,
        rules_dir: Path | None = None) -> dict:
    types: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for name in sorted(zipped.namelist()):
            if not re.fullmatch(r"[a-z0-9-]+\.json", name):
                raise ValueError(f"unexpected schema archive member: {name}")
            schema = json.loads(zipped.read(name))
            type_name = schema.get("typeName")
            if not isinstance(type_name, str) or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*", type_name
            ):
                raise ValueError(f"invalid resource type in {name}")
            if type_name in types:
                raise ValueError(f"duplicate resource type: {type_name}")
            types[type_name] = name
    if not types:
        raise ValueError("empty schema archive")
    manifest = {
        "source": url,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "archive": "CloudformationSchema.zip",
        "zip_sha256": hashlib.sha256(archive).hexdigest(),
        "types": types,
    }
    previous = None
    if (destination / "manifest.json").exists():
        old_manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        old_archive = (destination / old_manifest["archive"]).read_bytes()
        if hashlib.sha256(old_archive).hexdigest() != old_manifest["zip_sha256"]:
            raise ValueError("pinned schema archive hash mismatch; refusing to reconcile")
        previous = old_manifest, old_archive
    report = None
    if rules_dir is not None and (rules_dir / "ledger.json").exists():
        if previous is None:
            raise ValueError("a ledger exists but no previous schema archive is pinned")
        if previous[0]["zip_sha256"] != manifest["zip_sha256"] or previous[0]["region"] != region:
            report = reconcile(rules_dir, *previous, manifest, archive, manifest["retrieved_at"][:10])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / manifest["archive"]).write_bytes(archive)
    (destination / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"types": len(types), "zip_sha256": manifest["zip_sha256"], "reconcile": report}


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Pin all CloudFormation resource schemas for a Region")
    parser.add_argument("--region", default="ap-northeast-1")
    parser.add_argument("--output", type=Path, default=root / "schemas")
    parser.add_argument("--rules", type=Path, default=root / "rules",
                        help="rules directory whose review ledger follows the schema change")
    parser.add_argument("--no-reconcile", action="store_true",
                        help="pin the archive without updating the review ledger")
    parser.add_argument("--report", type=Path, help="write the type diff and ledger changes here")
    args = parser.parse_args(argv)
    result = update(args.region, args.output, None if args.no_reconcile else args.rules)
    summary = result["reconcile"]
    if args.report and summary is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Pinned {result['types']} CloudFormation resource types for {args.region}" +
          (f"; added {len(summary['added'])}, removed {len(summary['removed'])}, "
           f"changed {len(summary['changed'])}" if summary else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
