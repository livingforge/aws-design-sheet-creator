# AWS design review skill: usage

This skill contains an allowlisted Python runtime, separate Tokyo/us-east-1 CloudFormation acquisition locks, profiles/rules, small fictional examples, and focused tests. Copy only this skill into the chosen host location: `.agents/skills` for Codex, `.claude/skills` for Claude Code, or `.github/skills` for Copilot. Keep the contents together and preserve unrelated host settings. Development history, full project dossiers and large evaluation outputs are excluded.

## Install on Windows

The locked release requires Python 3.12 or newer, excluding 3.14.1 because the pinned networkx dependency excludes that interpreter. Windows/Python 3.12.10 is the tested platform. From the skill directory:

```powershell
& .\scripts\install.ps1
```

The script creates a new `.venv` and installs the package from its local source, with tested dependency constraints from `requirements.lock` and the official PyPI index. Before that it lists earlier installations and asks before removing them: this copy's existing `.venv`, `aws-design-review` copies of an older version in the `.claude`, `.agents`, `.github` and legacy `.codex` skill folders of the same project and of the user profile, and `aws-design-sheet` installed into the Python used for installation. Copies of the same or a newer version, or without a readable version, are listed and kept. Confirmed folders go to the Windows Recycle Bin, together with their schema caches; the new copy downloads the current archives. The package is removed with `pip uninstall`, which the Recycle Bin cannot restore; an editable install keeps its source folder. Nothing changes when the answer is no, when a folder is not on a local drive with the Recycle Bin enabled, when it would not fit there, or when the selected Python lives inside a folder to remove. In a non-interactive session the script stops after the list; `-Force` removes the listed items without asking. For optional free-text extraction, `-Llm` installs Anthropic support; this sends input text to an external API, needs separate credentials and may incur charges. It was not exercised in this release. The default local workflows need no API/AWS credentials. Add `-Tests` to install the constrained pytest dependency. The installer then runs `aws-design-bootstrap --all-regions`: initial network access is required to download the two exact pinned archives from the public official AWS regional URLs and build the local catalog. No AWS login is needed. The ZIP and generated schema/catalog files are not distributed.

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

When working from a different directory, use absolute paths for the CLI executable, input, and output. Set `--region` explicitly for a different region and provide a matching schema snapshot. For saved intermediate JSON, use `aws-design-check INPUT --output RESULT`. `status: COMPLETE` means the process finished; review individual verdicts and `coverage` for unresolved scope. Both commands export the design as CloudFormation templates and check them with cfn-lint, which the install script installs as a dependency; `--no-cfn-lint` skips it. The checker does not certify AWS deployability.

## Generate a design workbook (input v1)

The independent `aws-design-document` command creates a workbook before CFN exists:

```powershell
& .\.venv\Scripts\python.exe -m aws_design_sheet.document_cli examples/design-document-v1/design.yaml --environment dev --output output/my-design
```

Add `--cfn examples/design-document-v1/configuration.yaml` to compare explicit CFN logical-ID bindings, or select `--environment prod` for the sample overrides. Use a fresh output directory. The fictional samples are bundled under `examples/design-document-v1/`. Generate the input contract locally with `aws-design-document --schema input --schema-version 1.0`; version 1.1 requires the installed schema cache. Output: `design.xlsx`, `design.json`, `summary.json`. `GENERATED` means document generation succeeded; `NOT_EVALUATED` remains the design evaluation status.

The supported documentation catalog covers VPC, Subnet, SecurityGroup, EC2 Instance, RDS DBSubnetGroup, DBInstance and DBCluster. Input IDs and references are validated. Common settings and whole-setting environment overrides remain separate. Undecided/not-applicable decisions, explicit defaults, external references, unresolved expressions and secret references are distinct. Never enter secret values: use SECRET classification plus SECRET_REF with a secret:// or ssm:// reference. Do not put secrets in prose or identifiers. References are not fetched.

The 12-sheet layout includes requirements, inventory, service settings, connections, operations/recovery, open issues, differences, environment overrides and provenance. Long text continues on additional rows with the same item ID; strings are not formulas. A3 landscape printing is configured. Editing arbitrary Excel cells cannot update the input. The normalized document contract is independent of the checker's Design JSON, and cannot be passed directly to `aws-design-check`. CFN comparison does not evaluate deployability or network reachability.

## Review and verify check results

`aws-design-correct` records a user-requested correction with an author and reason; run `aws-design-correct --help` for its arguments. Rule maintenance uses `aws-design-review` and changes bundled rule files, so it is separate from a read-only design check.

The focused policy, AWS bridge and required-input tests are included. After installing with `-Tests`, run these from the skill directory:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

## Schema-driven design documents (1.1)

Use `python -m aws_design_sheet.document_cli examples/design-document-50/mixed.json --environment dev --output output/document-50` with a fresh output directory. Optional `--cfn examples/design-document-50/configuration.json` compares declarations. The index workbook links service volumes (`--volume-size 10`). Version 0.3.0 preserves the original 50 service groups and adds Cognito: At review, Tokyo had 51 groups / 608 resource types / 4058 writable top-level properties; us-east-1 had 51 / 640 / 4197. A later official archive can differ. These are generation inventories, not whole-service validation coverage. Secrets must be references. Small fictional examples are included. Export input contracts locally with `aws-design-document --schema input --schema-version 1.1`; developer evaluation scripts are not bundled.

The installer runs `aws-design-bootstrap --all-regions`. Locks cover ap-northeast-1 (Tokyo), ap-northeast-3 (Osaka) and us-east-1. Use `--check --all-regions` offline, or `--region ap-northeast-3` for one pinned region. Each archive, manifest, receipt and catalog stays in `schemas/.cache/<region>/<archive SHA-256>/<lock SHA-256>/`. Missing regional locks and corrupt or tampered caches fail explicitly, with no Tokyo fallback. Format-3 locks accept a newer official archive: setup prints `review_status` (REVIEWED_EXACT or DRIFTED_FROM_REVIEWED) and `review_drift` counts, the cache keeps `drift.json` with the added/changed/removed types, and the rule ledger is reconciled so changed types are review-required. Generation repeats the status in `summary.json` catalogs and adds a notice when drifted. Format-1/2 locks still stop on any archive change. Regional rule review status is retained separately; a Tokyo review is not approval in another region. A type keeps its Tokyo ledger state in another region only when `rules/schema-reviews.json` records a regional review of that region's exact type schema (SHA-256 of its canonical JSON); a schema-change record likewise covers one exact new type schema. Any other fingerprint, region or baseline re-opens the question. The Osaka lock carries 687 types recorded this way (schema identical to the reviewed Tokyo snapshot, no regional wording in their rules, references, checks or open questions); the others keep the regional question.

Each version 1.1 resource can set `region`; omission uses the selected environment region. Ordinary references must satisfy existing environment/account/region checks. Only CloudFront viewer certificates in ACM and explicitly CLOUDFRONT-scoped WAF in us-east-1 have narrow cross-region reference handling. Other account or physical-ID unknowns stay unresolved. A single `--cfn` comparison cannot represent a multi-region design and is rejected. Explicit `connections` of kind `DEPENDENCY` are checked for graph cycles; this does not infer CloudFormation DependsOn, stack dependencies or deployment order.

## Source states and machine-readable explanation (1.1)

Every 1.1 generation writes `review-report.json`, `review-report.md`, and the same report inside `design.json` and workbook sheet `実行サマリ根拠`. Read these before writing a narrative. `summary.json.review_report_file` points to the report. Source states cannot be recovered from normalized DECIDED status or from rationale prose.

When explicit original states and bindings are available, add `--source-trace trace.json`. The trace is a JSON list (or an object with a `rows` list). Example row:

```json
{"setting_id":"SET-012","kind":"CFN","item_ids":["subnet.AvailabilityZoneId"],"source_pointer":"/settings/11","source_snapshot":{"setting_id":"SET-012","kind":"CFN","status":"EXTERNAL_INPUT_REQUIRED","verification_status":"NOT_RUN"}}
```

IDs must be unique and match the snapshot; status and verification_status must be explicit strings. Every item binding must exist. APP rows must have empty item_ids; an unmapped CFN row needs an explicit exclusion_reason. The full snapshot can preserve other source fields. The original input is not modified. Saved `source-trace.json` preserves these rows. `source_status_counts` and `source_verification_counts` report original states separately from `normalized_status_counts`. Without a trace they stay empty and trace.status is NOT_PROVIDED. Trace validation checks identity/state/bindings only; source fidelity requires independent audit.

The object form may also carry the source's own approval: `{"rows": [...], "document_approval": {"status": "APPROVED", "status_text": "承認済", "approvers": ["..."], "date": "2026/06/05", "status_cell": "book.xlsx#表紙!C13"}}`, and any row may carry `"item_review": {"status": "ACCEPTED", "text": "OK", "pointer": "book.xlsx#VPC!E5"}`. Document statuses are APPROVED, IN_REVIEW, DRAFT, REJECTED, UNRECOGNIZED, NOT_RECORDED, NOT_CITED and FORMULA_NOT_ADOPTED; item statuses are ACCEPTED, CHANGES_REQUESTED, NOT_REVIEWED, UNRECOGNIZED, NOT_RECORDED and FORMULA_NOT_ADOPTED; other fields are strings or string lists. `review-report.json.source_review` reports `document_approval` (NOT_CITED for a trace without it, NOT_PROVIDED without a trace), `item_review_counts` and `generated_items_by_item_review` (NOT_PROVIDED or MIXED where rows lack or disagree). These are transcriptions of the source, not approval by this tool, and a blank is never read as approved.

`review-report.json.rule_review_causes` splits RULE_REVIEW_REQUIRED coverage into REGIONAL_APPLICABILITY (a type not yet reviewed for this region), SCHEMA_CHANGE (the official schema changed since the review) and OPEN_QUESTION (an existing ledger question). `counts` counts coverage rows and `resources` the distinct resources per cause.

`RESOURCE_REF` is supported. The unresolved reason `SYMBOL_TARGET_NOT_BOUND` describes a symbol without an explicit resource-ID binding, not an input-format limitation. Physical IDs are not fetched. Report APP business scope, unregistered requirements, unchecked conditions and regional review questions separately. CLI completion cannot establish actual host invocation: `host_acceptance` remains NOT_VERIFIED_BY_CLI, and whole_design_approval remains NOT_ESTABLISHED. Original NOT_RUN states are preserved even after local static evaluation.

Input decision status and value resolution are separate: `EXPRESSION_MATCH` is only expression equality and never deployment approval. Office/PDF source extraction and PDF export are not part of this minimal distribution. Workbook generation uses openpyxl and does not require Microsoft Excel.

## Basic design decisions and traceability (1.1)

One 1.1 input can hold both the basic design (policy prose) and the parameter sheet (settings). Optional `decisions` declare policies: stable `id`, `section`, `title`, `statement`, `status`, `rationale`, `alternatives`, `requirement_ids`, `policy_ids` (existing `project_policies`), `sources` and optional `applies_to` (`resources` and/or `types`, optional `environments`). `section` must be in `design_outline` (a list of `{id,title,required}`); when omitted the standard outline is used: overview, non-functional, account, network, compute, data, edge, security, monitoring, backup-dr, operations. Any setting, including a COMPOSITE `$design` leaf or an environment override, may list `decision_ids`. Unknown or duplicate links are structure errors. See `examples/basic-design/input.json`.

Every 1.1 generation writes `basic-design.md`: chapters in outline order, each decision with its realizing settings, a Mermaid diagram of declared connections and appendices. When decisions or an outline are declared, `decision-trace.json` (also in `design.json` and sheets `設計方針`, `方針トレース`, `方針指摘`) reports per decision `realization` (REALIZED, PARTIAL, NOT_REALIZED, LINKED, DOCUMENT_ONLY, NO_TARGET_IN_SCOPE, NOT_IN_ENVIRONMENT, UNDECIDED, NOT_APPLICABLE) and `mechanization` (DESCRIBED, TRACED, CHECKED). Findings are GAP (SECTION_EMPTY, DECISION_NOT_REALIZED, NO_TARGET_IN_SCOPE, REQUIREMENT_WITHOUT_DECISION, SETTING_WITHOUT_BASIS), CONFLICT (DECISION_UNDECIDED_BUT_SETTING_DECIDED, DECISION_NOT_APPLICABLE_BUT_LINKED, LINK_OUTSIDE_DECISION_SCOPE) or OPEN (DECISION_UNDECIDED, REALIZING_SETTING_UNDECIDED). Read `summary.json.design_decision_assessment` separately from other statuses; it does not change the exit code.

Only declared links are traced. Decision prose is never interpreted, no setting value is derived from a decision, and REALIZED only means each in-scope resource has a decided setting citing the decision, not that the policy is satisfied. `SETTING_WITHOUT_BASIS` covers top-level explicit values with no decision, rationale or source; REFERENCE connections document their RESOURCE_REF properties. Edit the input and regenerate instead of editing `basic-design.md`.

A decision with `applies_to` may declare `expansions`: `{property, mode (LITERAL, RESOURCE_REF or EXTERNAL_REF), value or ref, classification (not SECRET), environments, types, rationale}`. Only DECIDED decisions expand, only into absent top-level settings of in-scope resources (optionally narrowed by `types`). Explicit common or environment settings always win; a different explicit value is the CONFLICT `EXPANSION_OVERRIDDEN`, an equal one is MATCHED_EXPLICIT. Expanded items have `origin: decision`, the expansion's input pointer and the decision ID, and feed the checklist, project policies and AWS evaluation like ordinary settings. Two expansions for one setting, unknown properties, sensitive properties and invalid references are structure errors. `decision-trace.json.expansions` and sheet `方針展開` list every result.

## Workbook proposals (1.1)

Service setting sheets of 1.1 workbooks have edit columns `修正案（値）`, `修正理由` and `適用先（共通/環境）`; sheet `概要` holds `@import-key` (input SHA-256 and environment). Reviewers type only into those columns. `aws-design-changes propose INPUT GENERATED_DIR_OR_XLSX... --output proposal.json` reads them without modifying the input: a value is JSON when it parses, otherwise text; `未決定` makes the setting UNDECIDED; the reason is required; the target defaults to where the value came from. Formulas, dates, secret-like values, COMPOSITE/secret targets, several cells for one item, unchanged values and results that fail input validation are listed in `rejected` with a code. A workbook generated from a different input fails as STALE_WORKBOOK.

`aws-design-changes apply INPUT proposal.json --output NEW_INPUT.json --approver NAME (--all | --change ID ...)` writes a new JSON input and appends `change_log` records (before, after, reason, approver, UTC time, proposal and workbook SHA-256). It refuses a changed input or target (STALE_PROPOSAL), an existing output and a missing approver. `--generate DIR` regenerates the proposal environment; read its decision trace and checklist with the change. Decisions, requirements and other prose are edited in the input, not imported from workbooks.

## External design sheets parsed by ARP4

`aws-design-external` turns an external per-service Excel design sheet into a 1.1 input. It does not read Office files itself and ARP4 is not bundled: the sheet must already be parsed by ARP4 (`extraction.json`, `document.yml` and a structure view whose ARP review is accepted). Agents decide what each cell means and cite cells by ID only; the CLI checks every claim against the extraction and copies the values.

1. Worker (`aws-sheet-extract-worker` agent for Claude Code and Copilot) reads `aws-design-external schema --kind items` and `aws-design-external view --extraction E --structure S --document D`, writes the items file and fixes it until `aws-design-external check … --items ITEMS [--dictionary DICT]` reports PASS. Every non-empty cell, including hidden sheets, is a resource name or evidence, an item, an extension, an unmapped item or a reasoned exclusion.
2. Reviewer (`aws-sheet-extract-reviewer`, a different actor) compares the claims with the cells and records `aws-design-external review … --decision accepted --actor NAME --reason TEXT --output REVIEW`. The CLI refuses the worker's actor name and a failing check; `build` rejects a review of a different items file. Codex has no bundled agent definitions; run the two roles as separate sessions with distinct actor names.
3. Mapping proposals become dictionary entries only through `aws-design-external approve … --approver NAME (--all | --item ID ...) --output NEW_DICT`, with an approver the user names. Never approve as the agent.
4. `aws-design-external build … --dictionary DICT --review REVIEW --base BASE --source ORIGINAL.xlsx --output FRESH_DIR` writes `input.json`, `source-trace.json`, `external-mapping.json`, `external-coverage.json` and `external-trace.xlsx`. `base.json` holds `system` and `environments` (with regions); they are never inferred from the sheet. `--source` only hashes the original before and after and stops on a mismatch with the ARP record. Exit 0 is COMPLETE, 3 is INCOMPLETE (outputs written), 2 is an input or check error.
5. Generate as usual: `aws-design-document out/input.json --environment ENV --output FRESH_DIR --source-trace out/source-trace.json`.

If the sheet has an approval block, the items file cites it as `approval` (`status_cell`, `approver_cells`, `date_cell`, `note_cells`); an item may cite its row's review column as `review_cell`. The CLI transcribes them with built-in words (承認済/承認/Approved, レビュー中, ドラフト, 差戻し …; OK/済/確認済, NG/要修正, 未/未確認 …) and the dictionary's user-approved `approval_words` and `review_words`. A blank is NOT_RECORDED, other words are UNRECOGNIZED with warning `APPROVAL_WORD_UNKNOWN` or `REVIEW_WORD_UNKNOWN`, and a review cell cannot be the value cell (`REVIEW_CELL_IS_VALUE`). `source-trace.json` carries `document_approval` and `item_review`, `external-coverage.json.source_review` counts them, and `import_status` does not depend on them.

States must match the cell: LITERAL, UNDECIDED / NOT_APPLICABLE / DEFAULT only for such words in the cell, BLANK for an empty value cell, FORMULA (never its cached result), RESOURCE_REF when the text equals another resource's name cell, SECRET_REF for `secret://` or `ssm://`, and SECRET_VALUE for a clear-text secret. BLANK, FORMULA and SECRET_VALUE are not written to the input; secret values are masked in every output. Missing relations such as a VPC or subnet group are `unmapped` with `NEEDS_CONFIRMATION` and a follow-up, not guesses. Paths are checked against the regional catalog, including required members of array elements (`INCOMPLETE_ELEMENT`). Error codes name cells, never values.

`import_status` is COMPLETE only with an accepted review, no unapproved proposals, no unwritten items and no unmapped items. It describes the conversion, not design approval. ARP4 does not extract data validations, defined names, protection or external links; `unchecked_scope` records them as NOT_EXTRACTED_BY_ARP. Secret values still reach ARP4's extraction and the worker's context, so replace secrets with references in the original before import. JSON outputs are byte-identical for the same extraction, structure, items, dictionary, base and schemas; the agents' readings can differ between runs. Nothing is written back to the original. `examples/external-sheet/` is a fictional fixture with a fake test password.

## Required-input checklist (1.0 and 1.1 inputs)

Document generation now also writes `checklist.json`, embeds it in `design.json`, and adds required-input and evidence sheets to the index workbook. Run `python -m aws_design_sheet.document_cli examples/required-input-checklist/design.json --environment prod --output output/required-inputs` in a fresh destination; `repaired.json` is the repair control. Generation can succeed with missing or undecided inputs. Read `summary.json.input_completeness` separately from `GENERATED` and `NOT_EVALUATED`.

The checklist reuses pinned CFN required constraints and directly applicable registered cfn-lint error JSON schemas. Necessity, three-valued condition results, input state, value resolution and verdict remain separate. Read-only outputs are excluded. One-of alternatives are not all made mandatory. Unknown conditions, unresolved references, empty values and unsupported preprocessing require review. `OMITTED` explicitly records omission; an input's NOT_APPLICABLE declaration cannot waive an AWS-required field. CFN values and defaults never fill absent design inputs.

Optional `required_inputs` declarations bind a requirement ID, resource ID, `/properties/...` pointer, source IDs, environments and optional JSON Schema `when` predicate. Explicit `confirmation: CONFIRMED` plus sources are needed for a firm project verdict. Sources missing or unconfirmed interpretations remain UNKNOWN/review. `allow_documented_default` only permits a project requirement to accept an explicit DEFAULT with direct top-level pinned-schema default metadata; it cannot exempt AWS-required obligations. The sample shows the full contract. CLI `--schema input --schema-version 1.1` prints it.

Counters describe obligation rows and unique input paths, not all catalog properties or complete AWS coverage. General value correctness, conditions missing from schemas, Python-only/warning rules, project expected-value policies and deployment are outside this checklist. Project values use the separate policy layer below. The included missing/repair controls do not certify a real design.

### Optional local AWS evaluation bridge

Add `--evaluate` to `aws-design-document` to run the existing Checker and cfn-lint on the selected environment's effective design settings, for input 1.0 or 1.1. CFN remains optional and is used only for comparison: it never supplies missing design values. Invalid equal Runtime/TLS values can therefore be MATCH while AWS evaluation reports a finding. No project expected-value or live AWS checks are added.

Generation, comparison, required-input completeness, evaluator execution and AWS findings are separate axes. `evaluation.json`, normalized `design.json` and the index workbook's AWS評価 / AWS未検査 / AWS評価根拠 sheets retain results, unknowns, IDs, input pointers and source links. Evaluation is opt-in; existing calls remain NOT_EVALUATED. CLI returns 3 on evaluator failure or unsupported-region skip, 2 on structure/output errors, and 0 for completed generation/evaluation even when findings exist. Check `aws_assessment` and severities; there is no overall PASS.

Undecided/default/expression/secret values are unresolved, and so are external references unless bound as below. Internal references preserve declared targets but infer neither physical values nor Ref/GetAtt attributes. Synthetic lint templates are isolated per resource, marked non-deployable, and record placeholder mappings without defaults. Stack/account context, business requirements, application behavior, real permissions, performance and deployment remain outside scope. Conditional findings affected by unknown context are retained for review. Never reuse an existing output directory.

### Local values for external references

`--external-bindings FILE` supplies values the designer knows for EXTERNAL_REF settings (an existing VPC ID, a KMS key ARN). Format: `{"binding_version": "1.0", "environment": "prod", "bindings": [{"ref": "kms-key-alias/portal", "value": "alias/portal", "source": "key inventory 2026-10"}]}`; `environment` is optional and must match. Each use of a bound ref is checked against the regional pinned schema's JSON type: BOUND values become evaluation inputs for `--evaluate` (coverage `EXTERNAL_VALUE_BOUND`), SHAPE_MISMATCH and UNBOUND stay unknown (`BRIDGE_UNKNOWN_VALUE`, reason `EXTERNAL_REF_BINDING_SHAPE_MISMATCH` for a mismatch). Every ARN in a bound value must also carry the resource's region and partition (global ARNs such as S3 and IAM have none); CloudFront viewer ACM certificates and WebACLs must be in us-east-1. Otherwise the use is REGION_MISMATCH with `expected_region` and the ARN regions found, and stays unknown (`EXTERNAL_REF_BINDING_REGION_MISMATCH`). Backup copy destinations, KMS replica primary keys and RDS cross-region replica sources point elsewhere by design: they stay BOUND and record `cross_region`. With `--evaluate`, decided literal ARNs in the design get the same region test as rule `DOCUMENT_ARN_REGION` (stage `declared_regions`): FAIL (ERROR) for a CloudFront certificate or WebACL outside us-east-1, NEEDS_REVIEW (WARNING) for any other ARN whose region or partition differs from its resource, PASS for the fixed-region and by-design properties; matching ARNs add no row. The design input and workbook keep the reference. `review-report.json.external_bindings` and `summary.json.external_bindings` give the counts and unused refs. Nothing is fetched from AWS: existence, ownership and current state stay unverified. Duplicate refs, secret-like values, a ref also used by SECRET_REF or a SECRET setting, sensitive properties and a different environment stop with `BINDING_ERROR` (exit 2); the message names codes and refs, never values.

### Explicit project policies

Input 1.0/1.1 may declare `project_policies`: each has a stable id, requirement_id, resource_id, writable property JSON Pointer `path`, `operator` (EQUALS or IN), scalar `values`, explicit environments, sources, rationale, and confirmation (default UNCONFIRMED). Optional `when` is a conjunction of up to 16 predicates of the same form on the same resource. Rules are human mappings; no prose or arbitrary expression/code is executed. Array `*` selects every member; empty selections and unknown values require review. Numbers, booleans, empty strings and null are distinct.

Declared policies run during document generation. `--evaluate` additionally runs the independent AWS layer; optional CFN only supplies comparison data. Missing/default/Ref/GetAtt/internal/external/secret values are never filled or resolved for policy checks. PROJECT_POLICY failure says this project's choice was violated, not that AWS universally prohibits the value. Q02-style BlockPublicAcls=false is not proof of public exposure.

`policy_exceptions` require an id, one policy_id, concrete paths within its selector, explicit environments, reason, sources and confirmation. Confirmed exceptions turn known mismatches into EXEMPTED, never PASS; unknowns cannot be waived into success. Invalid syntax, references or exception scope produce POLICY_CONFIGURATION_ERROR (exit 2); evaluator failure produces FAILED/ERROR (exit 3). No credential values or exception text are logged on errors.

Inspect `project_policy_status`, `project_policy_assessment`, `project-policy.json`, and workbook 案件方針 / 案件方針根拠 / 案件要件範囲. IDs, declaration/value pointers, conditions, sources and exceptions are retained. Unregistered requirements remain listed; COMPLIANT_WITHIN_DECLARED_SCOPE is never whole-requirement or whole-design approval. See `examples/project-policies/design.json` and `noncompliant.json`. APP business controls, real AWS validation and prose extraction remain outside scope.

```powershell
& .\.venv\Scripts\aws-design-document.exe .\examples\project-policies\noncompliant.json --environment prod --output .\output\policy-review --evaluate
```

The example completes generation and AWS evaluation while recording NONCOMPLIANT in the separate project policy assessment. Treat the input as fictional, not a deployable configuration.

## Immutable official schema cache

`schemas/schema-lock.json` fixes the source URL, region, review time, tool version, ZIP SHA-256, previous type fingerprints and expected generated catalog/rule hashes. Bootstrap records the actual retrieval timestamp in `schemas/.cache/<hash>/schemas/manifest.json`, with its tool version and source. The sibling `catalog.json`, `reconciliation.json`, `rules/` and `generation.json` record the locally generated results. No ZIP members are extracted to filesystem paths.

Use `aws-design-bootstrap --check` to verify an existing cache offline. Re-running `aws-design-bootstrap` verifies and reuses it without network access or changes. After a failed first setup, retry bootstrap from the already installed environment; rerunning the installer itself intentionally refuses an existing `.venv`. Partial downloads and failed generation directories remain in `schemas/.downloads/`. Existing or corrupt cache directories are never silently replaced. Preserve a damaged cache elsewhere or install a fresh skill copy before recovering.

If AWS changes the public URL contents, acquisition stops with a hash mismatch. A maintainer must review the new schema, regenerate the lock/catalog/rule expectations and rerun regressions; users should install that reviewed release in a new directory. Never remove the pin. Old generations and unrelated files are preserved. Base rule edits also invalidate the reviewed lock instead of silently using an inconsistent catalog. The released `aws-design-schemas` default destination cannot overwrite this contract.

Installed local generation, required-input/policy checks and AWS static evaluation operate offline. Optional LLM extraction and new source-document retrieval do not. Missing or invalid schemas cause a setup/configuration failure, never a PASS. The live host apps themselves are not covered by Python CLI tests.

The official URL is mutable and is not a versioned archive service. After it changes, the same locked ZIP may no longer be obtainable for a fresh install. Preserve a verified cache for repeatable offline runs, or use a newly reviewed release; do not weaken hash validation.
