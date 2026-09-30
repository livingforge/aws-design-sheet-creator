# AWS design review skill: usage

This skill bundles the Python application, a pinned Tokyo-region CloudFormation schema, design profiles, rule data, examples, and the full test suite. Copy one host folder (`.codex`, `.claude`, or `.github`) into a project. Keep the contents of `skills/aws-design-review/` together.

## Install on Windows

Python 3.11 or newer is required. From the skill directory:

```powershell
& .\scripts\install.ps1
```

The script creates `.venv` inside this skill directory and installs the bundled Python package and dependencies. For optional Claude free-text extraction, run `& .\scripts\install.ps1 -Llm` and configure Anthropic API credentials. The line-format extractor needs no API credentials. If you move the copied skill after installation, recreate `.venv`.

## Run a check

The default extractor accepts UTF-8 lines such as:

```text
VPC main: CidrBlock=10.0.0.0/16; EnableDnsSupport=false
Subnet private-a: Vpc=main; CidrBlock=10.0.1.0/24; AvailabilityZone=ap-northeast-1a
```

Formal CloudFormation resource type names can also be used. Run from the skill directory, replacing the sample paths and metadata with the user's inputs:

```powershell
& .\.venv\Scripts\aws-design-run.exe .\examples\network.txt --project sample --environment prod --account 111111111111 --intermediate .\output\design.json --result .\output\result.json
& .\.venv\Scripts\aws-design-excel.exe .\output\result.json --design .\output\design.json --output .\output\report.xlsx
```

When working from a different directory, use absolute paths for the CLI executable, input, and output. Set `--region` explicitly for a different region and provide a matching schema snapshot. For saved intermediate JSON, use `aws-design-check INPUT --output RESULT`. `status: COMPLETE` means the process finished; review individual verdicts and `coverage` for unresolved scope. The checker does not certify AWS deployability.

## Review and verify

`aws-design-correct` records a user-requested correction with an author and reason; run `aws-design-correct --help` for its arguments. Rule maintenance uses `aws-design-review` and changes bundled rule files, so it is separate from a read-only design check.

The source and tests are included. To run the suite after installation:

```powershell
& .\.venv\Scripts\python.exe -m pip install pytest
& .\.venv\Scripts\python.exe -m pytest -q
```
