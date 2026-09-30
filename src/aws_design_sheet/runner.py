"""Text-to-intermediate-to-results local pipeline."""
from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from pathlib import Path

from .checker import Checker
from .extractor import LineExtractor, TextSource
from .memory import peak_rss_bytes


def run_text(sources: list[TextSource], *, project: str, environment: str,
             account: str, region: str, schema_dir: Path, profile_path: Path,
             ledger_path: Path | None = None, ruleset_path: Path | None = None,
             references_path: Path | None = None, extractor=None):
    tracemalloc.start()
    start = time.perf_counter()
    checker = Checker(schema_dir, profile_path, ledger_path, ruleset_path, references_path)
    loaded = time.perf_counter()
    extractor = extractor or LineExtractor(checker.reference_types)
    if hasattr(extractor, "reference_catalog") and not extractor.reference_catalog:
        extractor.reference_catalog = dict(checker.reference_types)
    design = extractor.extract(
        sources, project=project, environment=environment, account=account, region=region)
    extracted = time.perf_counter()
    result = checker.check(design)
    checked = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result["metrics"] = {"extraction_seconds": round(extracted - loaded, 6),
                         "schema_load_seconds": round(loaded - start, 6),
                         "check_seconds": round(checked - extracted, 6),
                         "peak_bytes": peak, "process_peak_rss_bytes": peak_rss_bytes(),
                         "resources": len(design.resources),
                         "fields": sum(len(r.fields) for r in design.resources),
                         "relations": len(design.relations)}
    return design, result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract and check UTF-8 design notes")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="ap-northeast-1")
    parser.add_argument("--intermediate", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--profile", type=Path, default=root / "profiles/vpc-subnet.json")
    parser.add_argument("--ledger", type=Path, default=root / "rules/ledger.json")
    parser.add_argument("--ruleset", type=Path, default=root / "rules/ruleset.json")
    parser.add_argument("--references", type=Path, default=None,
                        help="reference catalog (default: rules/references.json when present)")
    parser.add_argument("--extractor", choices=["line", "llm"], default="line",
                        help="line: deterministic line grammar; llm: free text via Claude (needs the llm extra)")
    parser.add_argument("--model", default=None, help="Claude model for --extractor llm")
    args = parser.parse_args(argv)
    try:
        extractor = None
        if args.extractor == "llm":
            from .llm_extractor import MODEL, LlmExtractor
            extractor = LlmExtractor(model=args.model or MODEL)
        sources = [TextSource(id=f"doc-{i}", name=path.name, version="1",
                              text=path.read_bytes().decode("utf-8-sig"))
                   for i, path in enumerate(args.inputs, 1)]
        design, result = run_text(sources, project=args.project, environment=args.environment,
                                  account=args.account, region=args.region,
                                  schema_dir=args.schemas, profile_path=args.profile,
                                  ledger_path=args.ledger, ruleset_path=args.ruleset,
                                  references_path=args.references, extractor=extractor)
        if extractor is not None and extractor.rejected:
            result["extraction_rejected"] = extractor.rejected
        args.intermediate.parent.mkdir(parents=True, exist_ok=True)
        args.intermediate.write_text(design.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        result = {"status": "FAILED", "diagnostic": str(exc), "results": [], "coverage": []}
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
