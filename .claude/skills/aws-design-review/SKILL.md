---
name: aws-design-review
description: Create AWS design workbooks from structured input, identify required-input gaps, check explicitly declared project policies, and optionally run local AWS static checks or compare CFN. Also review documented line-format design text or saved checker JSON. Use for AWS design generation and review, not deployment or direct Office/PDF extraction.
---

# AWS design review

This `SKILL.md` directory is the package root. Keep `pyproject.toml`, `src/`, `schemas/`, `profiles/`, and `rules/` together. Use the installed CLI in this directory's `.venv`, with absolute input/output paths when running from another working directory. Read [references/usage.md](references/usage.md) for contracts and examples. If installation is needed, use `scripts/install.ps1` on Windows; dependencies come from PyPI. The installer refuses an existing environment and never deletes it. Do not enable optional LLM extraction without the user's request.

Initial setup also downloads the reviewed Tokyo schema from AWS's public official URL and generates the local catalog. It requires network access, no AWS credentials and no AWS account operations. The archive and generated schema catalog are not bundled. Run `aws-design-bootstrap --check` for an offline integrity check; use `aws-design-bootstrap` to retry a failed first acquisition. If the upstream hash changed, stop and report that a reviewed release/lock regeneration is needed. Never remove the hash check, refresh an existing cache silently, or treat missing schema data as a successful evaluation. Cached local workflows work offline after dependencies and schemas are installed. Preserve failed attempts and old cache generations.

## Choose the input contract

- Structured generation input (`schema_version` 1.0 or 1.1 with `system`, `environments`, `resources`): run `aws-design-document INPUT --environment ENV --output FRESH_DIRECTORY`. This creates workbooks and a required-input checklist. Confirm only missing environment/output choices that cannot be inferred. If asked to evaluate AWS validity, add `--evaluate`; this is local static analysis and requires no AWS credentials. Optional `--cfn FILE` compares declared bindings, never fills missing values.
- Project requirements: use the input's explicit `project_policies` declarations. They run during generation. Do not infer executable policies from prose, silently mark a declaration CONFIRMED, or invent expected values or sources. `required_inputs` describes presence obligations; `project_policies` compares known values. Follow the separate contracts in the usage reference.
- Documented line-format text: use `aws-design-run` as described below.
- Saved checker intermediate JSON: use `aws-design-check`. Generated `design.json` is a different contract and must not be passed to that command.
- Free prose or Office/PDF: explain the supported input contract. This package does not directly extract Office/PDF. Optional Anthropic extraction sends the text to an external API, needs separate credentials and may incur charges; it is not the default.

## Read the separate results

For document generation, inspect `summary.json`, `checklist.json`, optional `project-policy.json`, and optional `evaluation.json`. Report generation status, CFN comparison, `input_completeness`, `project_policy_status`/`project_policy_assessment`, and `evaluation_status`/`aws_assessment` separately. GENERATED and COMPLETE describe execution, not approval. A zero exit code can include FAIL findings; exit 2 means input/configuration/output errors, and 3 means an evaluator failed or AWS evaluation was skipped as unsupported. Do not hide those failures.

Give each relevant finding's ID, resource/property, condition, source and input pointer. Report missing, unknown, undecided, referenced and unregistered requirements explicitly. Exceptions are EXEMPTED, not PASS. Even COMPLIANT_WITHIN_DECLARED_SCOPE does not establish whole-requirement coverage. BlockPublicAcls=false by itself does not prove public access. Never equate CFN equality, an empty findings list or a generated workbook with deployment safety.

Keep each run in a fresh output directory. Do not edit source inputs unless requested. Never fetch secret references, invent physical IDs/defaults, run AWS deployment commands, install cloud credentials or upload the user's source/result files as part of this skill. Inputs must use secret references rather than secret values; output reports contain ordinary design values and must stay in the user's chosen location.

## Existing text/checker workflow

For line-format UTF-8 text, run `aws-design-run` with input path, `--project`, `--environment`, `--account`, `--intermediate`, and `--result`. Ask only for missing project, environment, or account values that cannot be inferred from the user's material; do not invent an account ID. The default region is `ap-northeast-1`; pass `--region` when the user specifies another region, and check that the pinned schema snapshot matches. For saved intermediate JSON, use `aws-design-check INPUT --output RESULT`. Both commands also export the design as CloudFormation templates and run cfn-lint on them; its findings appear as `CFN_LINT.<rule id>` results, and `--no-cfn-lint` skips this step. Use absolute input and output paths when invoking a CLI from a different working directory. Write generated results to the user's requested location or their project's output directory.

The default `line` extractor parses the documented line grammar. Free prose requires the optional `--extractor llm` installation and Anthropic credentials; use it when the user requests free prose extraction. Do not silently reinterpret prose as line-format input. This package does not read Office or PDF source files directly.

Read the result JSON before reporting. `status: COMPLETE` means the check ran, not that the design passed. Summarize `FAIL`, `ERROR`, and `NEEDS_REVIEW` from `results`; include rule ID, resource, field path, and reason. Resolve `evidence_ids` against the intermediate JSON's `evidence` entries to cite the source line and excerpt. Report relevant `coverage` entries and unprocessed input separately. `CFN_LINT_*` coverage entries mark cfn-lint findings left out because a value is unknown in the design, a reference attribute is not recorded, or the target is in another template. Distinguish the pinned schema and registered rules from conditions left for human review. Give the paths to the result and intermediate JSON, and offer `aws-design-excel RESULT --design INTERMEDIATE --output REPORT.xlsx` when a spreadsheet would help.

Do not edit source design files or merge rule reviews as part of a read-only design check. A user-requested correction can use `aws-design-correct` so the change and its reason are recorded; see [references/usage.md](references/usage.md) for the command.
