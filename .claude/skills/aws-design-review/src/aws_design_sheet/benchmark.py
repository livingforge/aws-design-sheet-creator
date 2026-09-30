"""Measure extraction, schema loading, checking, and peak Python memory."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

from .extractor import TextSource
from .runner import run_text


def benchmark(counts: list[int], schema_dir: Path, profile_path: Path) -> dict:
    measurements = []
    for count in counts:
        if not 1 <= count <= 4096:
            raise ValueError("subnet count must be between 1 and 4096")
        start = int(ipaddress.IPv4Address("10.0.0.0"))
        lines = ["VPC main: CidrBlock=10.0.0.0/16; EnableDnsSupport=false"]
        for i in range(count):
            address = ipaddress.IPv4Address(start + i * 16)
            lines.append(f"Subnet subnet-{i}: Vpc=main; CidrBlock={address}/28; MapPublicIpOnLaunch=false")
        _, result = run_text([TextSource(id="benchmark", name="generated", version="1",
                                         text="\n".join(lines))],
                             project="benchmark", environment="prod", account="000000000000",
                             region="ap-northeast-1", schema_dir=schema_dir, profile_path=profile_path)
        measurements.append({"subnets": count, **result["metrics"],
                             "verdicts": result["summary"], "uncovered": len(result["coverage"])})
    return {"benchmark_version": "1", "measurements": measurements}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark line extraction and checks")
    parser.add_argument("--counts", nargs="+", type=int, default=[10, 100, 1000])
    parser.add_argument("--output", type=Path)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--profile", type=Path, default=root / "profiles/vpc-subnet.json")
    args = parser.parse_args(argv)
    result = benchmark(args.counts, args.schemas, args.profile)
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
