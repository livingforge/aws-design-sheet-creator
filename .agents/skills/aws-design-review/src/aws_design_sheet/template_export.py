"""Write a generated design into the organisation's own Excel template.

A mapping file names template sheets and what goes where. A `table` block appends one row
per review-pack row of the selected resource types under a header row; a `form` block copies
a template sheet once per resource and writes chosen properties into fixed cells. Values,
states and sources come from review-pack.json, so the template shows the same reading,
provenance and evidence as the review pack. Text is written as data, never as formulas;
the template file itself is not changed.
"""
import argparse
import json
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

FIELDS = {'resource_id', 'resource_type', 'property', 'value', 'state', 'tier', 'documents', 'evidence_at', 'evidence', 'reasons', 'priority', 'item_id', 'components', 'requirements'}


class InputError(ValueError):
    pass


class Table(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: str = Field(pattern='^table$')
    sheet: str
    start_row: int = Field(ge=1)
    columns: dict[str, str]
    resource_types: list[str] = Field(default_factory=list)


class Form(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: str = Field(pattern='^form$')
    sheet: str
    resource_type: str
    title: str = '{resource_id}'
    cells: dict[str, str]
    name_cell: str | None = None
    remove_template_sheet: bool = True


class Mapping(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mapping_version: str
    blocks: list[Table | Form] = Field(min_length=1)


def field(row, name):
    value = row.get(name)
    if name == 'state':return row.get('state') or ''
    if name == 'tier':return row.get('tier_ja') or ''
    if name == 'priority':
        from .review_pack import PRIORITIES
        return PRIORITIES.get(row['priority'], row['priority'])
    if isinstance(value, list):return '、'.join(str(v) for v in value)
    return '' if value is None else str(value)


def put(sheet, ref, value):
    cell = sheet[ref]
    cell.value = value
    if isinstance(value, str):cell.data_type = 's'


def export(template_path, mapping, pack, output):
    from openpyxl import load_workbook
    from openpyxl.utils import column_index_from_string
    book = load_workbook(template_path)
    counts = {}
    for block in mapping.blocks:
        if block.sheet not in book.sheetnames:raise InputError(f'UNKNOWN_SHEET: {block.sheet}')
        if isinstance(block, Table):
            for column, name in block.columns.items():
                column_index_from_string(column)
                if name not in FIELDS:raise InputError(f'UNKNOWN_FIELD: {name}')
            sheet = book[block.sheet];row_number = block.start_row
            for row in pack['rows']:
                if block.resource_types and row.get('resource_type') not in block.resource_types:continue
                for column, name in block.columns.items():put(sheet, f'{column}{row_number}', field(row, name))
                row_number += 1
            counts[block.sheet] = row_number - block.start_row
            continue
        template = book[block.sheet]
        resources = sorted({r['resource_id'] for r in pack['rows'] if r.get('resource_type') == block.resource_type and r['resource_id']})
        for resource_id in resources:
            copy = book.copy_worksheet(template)
            copy.title = block.title.format(resource_id=resource_id)[:31]
            rows = {r['property']: r for r in pack['rows'] if r['resource_id'] == resource_id}
            if block.name_cell:put(copy, block.name_cell, resource_id)
            for spec, ref in block.cells.items():
                prop, _, name = spec.partition('#')
                row = rows.get(prop)
                put(copy, ref, field(row, name or 'value') if row else '')
        counts[block.sheet] = len(resources)
        if block.remove_template_sheet and resources:book.remove(template)
    output = Path(output)
    if output.exists():raise InputError('output already exists; use a fresh path')
    book.save(output)
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design export', description='Write a generated design into an organisation Excel template')
    parser.add_argument('--pack', required=True, help='review-pack.json of a generation');parser.add_argument('--template', required=True)
    parser.add_argument('--mapping', required=True, help='JSON naming template sheets and the fields or cells to fill')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        mapping = Mapping.model_validate_json(Path(args.mapping).read_bytes())
        counts = export(args.template, mapping, json.loads(Path(args.pack).read_text(encoding='utf-8')), args.output)
        print(json.dumps({'output': args.output, 'filled': counts}, ensure_ascii=False));return 0
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2
    except ValueError as exc:
        print(json.dumps({'status': 'ERROR', 'message': 'MAPPING_INVALID', 'detail': type(exc).__name__}));return 2


if __name__ == '__main__':
    raise SystemExit(main())
