"""SNS FIFO topic name rule from the CloudFormation resource contract."""
from __future__ import annotations

from typing import Any

from .models import Design, FieldValue, Resource, ValueState


RULE_ID = "SNS_FIFO_TOPIC_NAME_SUFFIX"
FIFO_PATH = "/properties/FifoTopic"
NAME_PATH = "/properties/TopicName"


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


def evaluate_sns_fifo_topic_name_suffix(design: Design, resource: Resource) -> dict[str, Any]:
    """A user-supplied FIFO topic name must end in `.fifo`."""
    _ = design  # Common independent evaluator signature.
    fifo = resource.field(FIFO_PATH)
    name = resource.field(NAME_PATH)
    evidence = list(dict.fromkeys([*_evidence(fifo), *_evidence(name)]))

    def result(verdict: str, reason: str, *, path: str = NAME_PATH,
               dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::SNS::Topic":
        return result("NOT_APPLICABLE", "resource type does not match", path=FIFO_PATH)
    if fifo is None or fifo.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NOT_APPLICABLE", "FIFO topic is not requested", path=FIFO_PATH)
    if fifo.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "FIFO setting is unresolved", path=FIFO_PATH,
                      dependencies=[FIFO_PATH])
    fifo_value = fifo.selected().value
    if fifo_value is False:
        return result("NOT_APPLICABLE", "topic is standard")
    if fifo_value is not True:
        return result("NEEDS_REVIEW", "FIFO setting is not a known boolean", path=FIFO_PATH,
                      dependencies=[FIFO_PATH])
    if name is None or name.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NOT_APPLICABLE", "CloudFormation will generate the topic name")
    if name.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "explicit topic name is unresolved",
                      dependencies=[NAME_PATH])
    value = name.selected().value
    if not isinstance(value, str):
        return result("NEEDS_REVIEW", "explicit topic name is not a known string",
                      dependencies=[NAME_PATH])
    if value.endswith(".fifo"):
        return result("PASS", "explicit FIFO topic name has the .fifo suffix")
    return result("FAIL", "explicit FIFO topic name must end with .fifo")
