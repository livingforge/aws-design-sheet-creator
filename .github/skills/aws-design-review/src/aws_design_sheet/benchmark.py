"""Measure extraction, schema loading, checking, and peak Python memory."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from collections import Counter

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


def benchmark_alb(counts: list[int], schema_dir: Path, profile_path: Path, *, invalid: bool = False) -> dict:
    """Measure complete text extraction and explicit ALB forwarding chains.

    The oracle covers only the ALB matcher rule, not overall design validity.
    Timings are observations; no hardware-dependent performance threshold is imposed.
    """
    if any(not 1 <= count <= 1000 for count in counts):
        raise ValueError("ALB chain count must be between 1 and 1000")
    measurements = []
    prefix = "AWS::ElasticLoadBalancingV2::"
    for count in counts:
        lines = ["VPC main: CidrBlock=10.0.0.0/16"]
        for i in range(count):
            lines.extend([
                f"{prefix}LoadBalancer lb-{i}: Type=application; IpAddressType=ipv4",
                f"{prefix}TargetGroup tg-{i}: Protocol=HTTP; Port=80; VpcId=@AWS::EC2::VPC/main; "
                + 'Matcher=' + json.dumps({'HttpCode': '500' if invalid else '200-499'}),
                f"{prefix}Listener listener-{i}: LoadBalancerArn=@{prefix}LoadBalancer/lb-{i}; Protocol=HTTP; Port=80; "
                + 'DefaultActions=' + json.dumps([{'Type':'forward','TargetGroupArn':f'@{prefix}TargetGroup/tg-{i}'}]),
            ])
        _, result = run_text([TextSource(id="benchmark", name="generated-alb", version="1", text="\n".join(lines))],
            project="benchmark", environment="prod", account="000000000000", region="ap-northeast-1",
            schema_dir=schema_dir, profile_path=profile_path)
        observed = dict(Counter(f['verdict'] for f in result['results'] if f['rule_id'] == 'ELBV2_ALB_MATCHER_RANGE'))
        expected = {'FAIL' if invalid else 'PASS': count}
        measurements.append({'chains': count, **result['metrics'], 'status': result['status'],
            'verdicts': result['summary'], 'uncovered': len(result['coverage']),
            'matcher_observed': observed, 'matcher_expected': expected,
            'oracle_matches': observed == expected and result['status'] == 'COMPLETE',
            'versions': result.get('versions', {})})
    return {'benchmark_version': '2', 'workload': 'alb-invalid' if invalid else 'alb',
            'oracle_scope': 'ELBV2_ALB_MATCHER_RANGE only; generated partial designs do not establish deployability',
            'measurements': measurements}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark line extraction and checks")
    parser.add_argument("--counts", nargs="+", type=int, default=[10, 100, 1000])
    parser.add_argument("--workload", choices=["subnets", "alb", "alb-invalid"], default="subnets")
    parser.add_argument("--output", type=Path)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--profile", type=Path, default=root / "profiles/vpc-subnet.json")
    args = parser.parse_args(argv)
    result = (benchmark(args.counts, args.schemas, args.profile) if args.workload == "subnets" else
              benchmark_alb(args.counts, args.schemas, args.profile, invalid=args.workload == "alb-invalid"))
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0 if all(m.get('oracle_matches', True) for m in result['measurements']) else 1


if __name__ == "__main__":
    raise SystemExit(main())
