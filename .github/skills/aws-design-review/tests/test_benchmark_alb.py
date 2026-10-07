from pathlib import Path
import pytest
from aws_design_sheet.benchmark import benchmark_alb, benchmark, main

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('invalid',[False,True])
def test_alb_benchmark_resolves_chains_and_detects_bad_matcher(invalid):
    report = benchmark_alb([2],ROOT/'schemas',ROOT/'profiles/vpc-subnet.json',invalid=invalid)
    row = report['measurements'][0]
    assert row['oracle_matches']
    assert row['matcher_observed'] == {'FAIL' if invalid else 'PASS':2}
    assert row['resources'] == 7
    assert row['relations'] == 6


@pytest.mark.parametrize('count',[0,1001])
def test_alb_benchmark_bounds(count):
    with pytest.raises(ValueError,match='ALB chain count'):
        benchmark_alb([count],ROOT/'schemas',ROOT/'profiles/vpc-subnet.json')


def test_existing_subnet_benchmark_contract():
    report=benchmark([1],ROOT/'schemas',ROOT/'profiles/vpc-subnet.json')
    assert report['benchmark_version']=='1'
    assert report['measurements'][0]['subnets']==1


def test_cli_reports_oracle_failure(monkeypatch,capsys):
    monkeypatch.setattr('aws_design_sheet.benchmark.benchmark_alb',lambda *a,**k:{'measurements':[{'oracle_matches':False}]})
    assert main(['--workload','alb','--counts','1'])==1
    assert 'false' in capsys.readouterr().out
