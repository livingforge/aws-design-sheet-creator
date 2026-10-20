"""Describe input completeness without turning processing success into approval."""
from __future__ import annotations
from collections import Counter
from .models import Design, ValueState
from .checks.common.index import relations_from, resources_by_id

NOTE = "COMPLETEは処理完了。設計合格・承認・デプロイ可能性を示さない。項目への判定の存在も要件全体の評価完了ではない。"


def within(path, parent):
    return bool(path and parent) and (path == parent or path.startswith(parent + "/"))


def has_unknown(value):
    if isinstance(value, dict):
        return "$state" in value or any(has_unknown(v) for v in value.values())
    return isinstance(value, list) and any(has_unknown(v) for v in value)


def binding_state(design, binding):
    resource = resources_by_id(design)[binding.resource_id]
    states = []
    for f in resource.fields:
        if within(f.path, binding.path) or within(binding.path, f.path):
            selected = f.selected()
            if f.state != ValueState.KNOWN or selected is None:
                states.append(f.state.value)
                continue
            value = selected.value
            if f.path != binding.path and within(binding.path, f.path):
                try:
                    for part in binding.path[len(f.path) + 1:].split("/"):
                        token = part.replace("~1", "/").replace("~0", "~")
                        value = value[int(token)] if isinstance(value, list) else value[token]
                except (KeyError, IndexError, TypeError, ValueError):
                    states.append("UNKNOWN")
                    continue
            states.append("UNRESOLVED" if has_unknown(value) else "KNOWN_LITERAL")
    for rel in relations_from(design, resource.id):
        if within(rel.source_path, binding.path):
            states.append("RESOURCE_REFERENCE" if rel.target_resource_id else "UNRESOLVED_REFERENCE")
    return sorted(set(states)) or ["UNKNOWN"]


def build_input_scope(design: Design, results: list[dict]) -> dict:
    inventory = design.input_inventory
    output = {"version": "1", "note": NOTE, "design_approval": "NOT_ASSESSED",
              "inventory_provided": inventory is not None, "total_items": None,
              "inventory_complete": None, "source_document_ids": [], "items": [], "scope_notes": [],
              "evaluation_meaning": "Observed item findings are partial evidence. Only explicitly requested rule bindings can be compared; missing metadata stays UNKNOWN."}
    if inventory is None:
        output["reason"] = "入力台帳メタデータなし。設定全体の分母・業務範囲・明示省略を推定しない。"
        return output
    output.update(total_items=inventory.total_items, inventory_complete=inventory.complete,
                  source_document_ids=inventory.source_document_ids,
                  scope_notes=[s.model_dump(mode="json") for s in inventory.scope_notes])
    by_resource: dict = {}  # resource ID -> indexes of its results, in result order
    for i, f in enumerate(results):
        by_resource.setdefault(f.get("resource_id"), []).append(i)
    for item in inventory.items:
        row = item.model_dump(mode="json")
        row["value_states"] = ["EXPLICIT_OMISSION"] if item.presence == "EXPLICIT_OMISSION" else (
            ["NOT_REPRESENTED"] if item.representation == "NOT_REPRESENTED" else
            sorted({s for b in item.bindings for s in binding_state(design, b)}) or ["UNKNOWN"])
        # Descendant findings may inspect part of the item. Parent resource findings
        # are not proof that this individual setting was evaluated.
        indexes = sorted({i for b in item.bindings for i in by_resource.get(b.resource_id, ())
                          if within(results[i].get("path"), b.path)})
        row["observed_result_indexes"] = indexes
        row["observed_rule_ids"] = sorted({results[i]["rule_id"] for i in indexes})
        requested = item.check_rule_ids
        if item.applicability == "OUT_OF_SCOPE":
            state = "OUT_OF_SCOPE"
        elif not requested:
            state = "UNKNOWN_RULE_COVERAGE"
        elif not all(rule in row["observed_rule_ids"] for rule in requested):
            state = "REQUESTED_RULES_INCOMPLETE"
        elif any(results[i]["verdict"] in ("NEEDS_REVIEW", "ERROR") for i in indexes if results[i]["rule_id"] in requested):
            state = "REQUESTED_RULES_UNRESOLVED"
        else:
            state = "REQUESTED_RULE_RESULTS_AVAILABLE"
        row["evaluation_state"] = state
        output["items"].append(row)
    output["counts"] = {dimension: dict(Counter(row[dimension] for row in output["items"]))
                        for dimension in ("category", "presence", "representation", "applicability", "evaluation_state")}
    return output
