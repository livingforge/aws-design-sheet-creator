---
name: aws-design-review
description: Run the bundled AWS design sheet checker on UTF-8 design text or saved intermediate JSON, then explain findings, evidence, and unchecked scope. Use for requests to inspect or review AWS design information with this package.
---

# AWS design review

Find the package root that contains `pyproject.toml`, `schemas/`, `profiles/`, and `rules/`. Run its installed CLI from `.venv` (on Windows, `.venv/Scripts/*.exe`). If the environment has not been installed, follow the package `Readme.md` installation instructions.

For line-format UTF-8 text, run `aws-design-run` with input path, `--project`, `--environment`, `--account`, `--intermediate`, and `--result`. Ask only for missing project, environment, or account values that cannot be inferred from the user's material; do not invent an account ID. The default region is `ap-northeast-1`; pass `--region` when the user specifies another region, and check that the pinned schema snapshot matches. The accepted line syntax is documented in `Readme.md`. For saved intermediate JSON, use `aws-design-check INPUT --output RESULT`. Use absolute input and output paths when invoking a CLI from a different working directory.

The default `line` extractor parses the documented line grammar. Free prose requires the optional `--extractor llm` installation and Anthropic credentials; use it when the user requests free prose extraction. Do not silently reinterpret prose as line-format input. This package does not read Office or PDF source files directly.

Read the result JSON before reporting. `status: COMPLETE` means the check ran, not that the design passed. Summarize `FAIL`, `ERROR`, and `NEEDS_REVIEW` from `results`; include rule ID, resource, field path, and reason. Resolve `evidence_ids` against the intermediate JSON's `evidence` entries to cite the source line and excerpt. Report relevant `coverage` entries and unprocessed input separately. Distinguish the pinned schema and registered rules from conditions left for human review. Give the paths to the result and intermediate JSON, and offer `aws-design-excel RESULT --design INTERMEDIATE --output REPORT.xlsx` when a spreadsheet would help.

Do not edit source design files or merge rule reviews as part of a read-only design check. A user-requested correction can use `aws-design-correct` so the change and its reason are recorded; see `Readme.md` for the command.
