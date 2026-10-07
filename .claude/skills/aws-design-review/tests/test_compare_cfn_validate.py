import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.models import Design
from scripts.compare_cfn_validate import validate_result


ROOT = Path(__file__).resolve().parents[1]


def test_comparison_rejects_result_for_another_design():
    design = Design.model_validate_json((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    matching_hash = hashlib.sha256(design.model_dump_json(exclude_none=False).encode()).hexdigest()
    validate_result(design, {"status": "COMPLETE", "input_sha256": matching_hash})

    other_result = {"status": "COMPLETE", "input_sha256": "0" * 64}
    with pytest.raises(ValueError, match="does not match"):
        validate_result(design, other_result)

    with pytest.raises(ValueError, match="does not match"):
        validate_result(design, {"status": "COMPLETE"})
