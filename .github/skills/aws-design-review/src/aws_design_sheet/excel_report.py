"""Write check results (and optionally the checked design data) to an Excel workbook."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import unicodedata
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .models import Design

VERDICT_ORDER = ["ERROR", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE", "PASS"]
VERDICT_STYLES = {  # (fill, font) colours
    "PASS": ("C6EFCE", "006100"),
    "FAIL": ("FFC7CE", "9C0006"),
    "NEEDS_REVIEW": ("FFEB9C", "9C5700"),
    "NOT_APPLICABLE": ("EDEDED", "595959"),
    "ERROR": ("E4DFEC", "5B2C6F"),
}
STATE_STYLES = {
    "KNOWN": VERDICT_STYLES["PASS"],
    "MISSING": VERDICT_STYLES["FAIL"],
    "CONFLICT": VERDICT_STYLES["FAIL"],
    "INFERRED": VERDICT_STYLES["NEEDS_REVIEW"],
    "UNRESOLVED": VERDICT_STYLES["NEEDS_REVIEW"],
    "NOT_APPLICABLE": VERDICT_STYLES["NOT_APPLICABLE"],
    "REFERENCE": ("DDEBF7", "1F4E78"),  # logical reference to another resource
}
HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=14)
SECTION_FONT = Font(bold=True, size=11, color="1F4E78")
TOP = Alignment(vertical="top")
WRAP = Alignment(wrap_text=True, vertical="top")
MAX_CELL = 32767
NOTE = "検査済み範囲の合格は、設計全体の妥当性や AWS へのデプロイ可否を保証しない。"


def text(value: Any) -> str:
    """Render a JSON value for a cell; None stays empty and false/0 stay visible."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def put(ws, row: int, column: int, value: Any, *, style: tuple[str, str] | None = None,
        wrap: bool = False):
    if isinstance(value, str) and (utf16_length(value) > MAX_CELL or ILLEGAL_CHARACTERS_RE.search(value)):
        # Excel's limit is UTF-16 code units. Keep the original in indexed chunks,
        # including XML-forbidden characters encoded as JSON, rather than truncate.
        records = getattr(ws.parent, '_full_text', [])
        identifier = f'text-{len(records) + 1:05}'
        records.append((identifier, ws.title, f'{get_column_letter(column)}{row}', value))
        ws.parent._full_text = records
        preview = ILLEGAL_CHARACTERS_RE.sub('', value[:200])
        value = f'{preview}\n［全文: 長文 / {identifier}］'
    cell = ws.cell(row=row, column=column, value=value)
    if isinstance(value, str) and value.startswith("="):
        cell.data_type = "s"  # design text is data, never a formula
    if style:
        cell.fill = PatternFill("solid", fgColor=style[0])
        cell.font = Font(bold=True, color=style[1])
    cell.alignment = WRAP if wrap else TOP
    return cell


def utf16_length(value: str) -> int:
    return len(value.encode('utf-16-le')) // 2


def text_chunks(value: str, limit: int = 30000):
    chunk, size = [], 0
    for char in value:
        units = 2 if ord(char) > 0xffff else 1
        if size + units > limit:
            yield ''.join(chunk)
            chunk, size = [], 0
        chunk.append(char)
        size += units
    if chunk:
        yield ''.join(chunk)


def _full_text_sheet(wb):
    records = getattr(wb, '_full_text', [])
    if not records:
        return
    rows = []
    for identifier, sheet, cell, original in records:
        encoded = bool(ILLEGAL_CHARACTERS_RE.search(original))
        payload = json.dumps(original, ensure_ascii=False) if encoded else original
        chunks = list(text_chunks(payload))
        digest = hashlib.sha256(original.encode('utf-8')).hexdigest()
        rows.extend([identifier, sheet, cell, n, len(chunks), 'json' if encoded else 'text',
                     chunk, digest] for n, chunk in enumerate(chunks, 1))
    table(wb.create_sheet('長文'), ['全文ID', '元シート', '元セル', '分割番号', '分割数', '形式', '内容', '原文SHA256'],
          rows, [18, 20, 14, 12, 12, 10, 100, 68], wrapped={7})


def table(ws, headers: list[str], rows: list[list[Any]], widths: list[int], *,
          styled: dict[int, dict[str, tuple[str, str]]] | None = None,
          wrapped: set[int] = frozenset(), height_columns: set[int] | None = None):
    for column, (header, width) in enumerate(zip(headers, widths), 1):
        cell = put(ws, 1, column, header)
        cell.fill, cell.font = HEADER_FILL, HEADER_FONT
        ws.column_dimensions[get_column_letter(column)].width = width
    for row_number, row in enumerate(rows, 2):
        line_count = 1
        for column, value in enumerate(row, 1):
            styles = (styled or {}).get(column)
            put(ws, row_number, column, value, style=styles.get(value) if styles else None,
                wrap=column in wrapped)
            if column in (wrapped if height_columns is None else height_columns) and value is not None:
                length = lambda line: sum(2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in line)
                lines = sum(max(1, math.ceil(length(line) / max(1, widths[column - 1] - 2)))
                            for line in str(value).split('\n'))
                line_count = max(line_count, lines)
        # Excel itself caps row height at 409 points; full values remain in cells.
        ws.row_dimensions[row_number].height = min(409, max(22, 15 * line_count + 5))
    ws.row_dimensions[1].height = 30
    ws.sheet_view.zoomScale = 85
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(rows) + 1, 2)}"
    ws.print_title_rows = '1:1'
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.orientation = 'landscape'
    ws.page_setup.paperSize = ws.PAPERSIZE_A3
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.print_options.horizontalCentered = True


def build_workbook(result: dict, design: Design | None = None) -> Workbook:
    if design is not None and result.get("input_sha256") is not None:
        current = hashlib.sha256(design.model_dump_json(exclude_none=False).encode()).hexdigest()
        if result["input_sha256"] != current:
            raise ValueError("check result does not match intermediate data")
    resources = {r.id: r for r in design.resources} if design else {}
    documents = {d.id: d.name for d in design.documents} if design else {}
    evidence = {e.id: e for e in design.evidence} if design else {}

    def evidence_text(ids: list[str]) -> str:
        lines = []
        for evidence_id in ids:
            e = evidence.get(evidence_id)
            if e is None:
                lines.append(evidence_id)
                continue
            where = (f"L{e.start_line}" if e.start_line == e.end_line
                     else f"L{e.start_line}-{e.end_line}")
            lines.append(f"{documents.get(e.document_id, e.document_id)} {where}: {e.excerpt}")
        return "\n".join(lines)

    def resource_cells(resource_id: str | None) -> list[str]:
        resource = resources.get(resource_id)
        return [resource.type if resource else "", resource.name if resource else "",
                resource_id or ""]

    wb = Workbook()
    _summary(wb.active, result, design)
    ws = wb.create_sheet("検査結果")
    findings = sorted(result.get("results", []),
                      key=lambda r: VERDICT_ORDER.index(r["verdict"])
                      if r["verdict"] in VERDICT_ORDER else len(VERDICT_ORDER))
    table(ws, ["No", "判定", "重大度", "ルール ID", "リソース種別", "リソース名", "リソース ID",
               "項目パス", "期待値", "実際の値", "理由", "根拠", "依存する未確定項目"],
          [[number, r["verdict"], r.get("severity"), r["rule_id"],
            *resource_cells(r.get("resource_id")), r.get("path") or "",
            text(r.get("expected")), text(r.get("actual")), r.get("reason", ""),
            evidence_text(r.get("evidence_ids", [])), "\n".join(map(text, r.get("dependencies", [])))]
           for number, r in enumerate(findings, 1)],
          [7, 18, 10, 40, 24, 16, 13, 34, 18, 18, 36, 56, 22],
          styled={2: VERDICT_STYLES}, wrapped={9, 10, 11, 12, 13})

    ws = wb.create_sheet("未検査範囲")
    table(ws, ["No", "種別", "リソース種別", "リソース名", "リソース ID", "項目パス", "理由"],
          [[number, item["kind"], *resource_cells(item.get("resource_id")),
            item.get("path") or "", item.get("reason", "")]
           for number, item in enumerate(result.get("coverage", []), 1)],
          [7, 24, 24, 16, 13, 34, 70], wrapped={7})

    if design is not None:
        ws = wb.create_sheet("設計値")
        rows = []
        for resource in design.resources:
            if resource.template:
                meta = resource.template
                rows.append([resource.type, resource.name, resource.id, '/template',
                             meta.state.value, text({'id': meta.id, 'depends_on': meta.depends_on}),
                             evidence_text(meta.evidence_ids)])
            for field in resource.fields:
                selected = field.selected()
                if selected is not None:
                    shown, ids = text(selected.value), selected.evidence_ids
                else:
                    shown = "\n".join(text(c.value) for c in field.candidates)
                    ids = [i for c in field.candidates for i in c.evidence_ids]
                if field.default_intent:
                    shown = "(既定値に依存)" + (f"\n{shown}" if shown else "")
                    ids = ids + field.intent_evidence_ids
                rows.append([resource.type, resource.name, resource.id, field.path,
                             field.state.value, shown, evidence_text(ids)])
            for relation in design.relations:
                if relation.source_resource_id != resource.id:
                    continue
                target = resources.get(relation.target_resource_id)
                rows.append([resource.type, resource.name, resource.id, relation.source_path,
                             "REFERENCE" if target else "UNRESOLVED",
                             f"→ {target.type}/{target.name}" if target
                             else f"→ {relation.unresolved_name or ''}",
                             evidence_text(relation.evidence_ids)])
        table(ws, ["リソース種別", "リソース名", "リソース ID", "項目パス", "状態", "値", "根拠"],
              rows, [24, 16, 13, 34, 13, 34, 64],
              styled={5: STATE_STYLES}, wrapped={6, 7})
    review = result.get("review_summary")
    if review is not None:
        from .review_summary import validate_review_summary
        raw = result.get("results", [])
        validate_review_summary(review, raw, result.get('coverage', []))
        ordered = sorted(range(len(raw)), key=lambda i: VERDICT_ORDER.index(raw[i]['verdict'])
                         if raw[i]['verdict'] in VERDICT_ORDER else len(VERDICT_ORDER))
        row_numbers = {index: position + 1 for position, index in enumerate(ordered)}
        ws = wb.create_sheet("要確認一覧")
        # Normalize shared coverage sets by membership. Global coverage is stored
        # once, so every review can point to it without huge repeated cell values.
        memberships = {}
        for item in review['items']:
            for index in item['coverage_indexes']:
                memberships.setdefault(index, []).append(item['id'])
        groups = {}
        for index, item_ids in memberships.items():
            groups.setdefault(tuple(item_ids), []).append(index)
        item_groups = {item['id']: [] for item in review['items']}
        coverage_rows, association_rows = [], []
        for n, (item_ids, indexes) in enumerate(groups.items(), 1):
            group = f'coverage-{n:04}'
            coverage_rows.extend([group, index + 1, f'/coverage/{index}'] for index in indexes)
            for identifier in item_ids:
                item_groups[identifier].append(group)
                association_rows.append([identifier, 'coverage_group', group, len(indexes), ''])
        rows = []
        for item in review['items']:
            members = [raw[i] for i in item['result_indexes']]
            association_rows.extend([item['id'], 'result', row_numbers[i], 1, f'/results/{i}']
                                    for i in item['result_indexes'])
            short_indexes = ', '.join(str(i + 1) for i in item['coverage_indexes'])
            coverage_display = (short_indexes if len(short_indexes) <= 1000 else
                                '未検査関連: ' + ', '.join(item_groups[item['id']]))
            rows.append([item['id'], item['severity'], len(members), item['unknown'], item['why'], item['action'],
                         ', '.join(str(row_numbers[i]) for i in item['result_indexes']),
                         '\n'.join(item['result_refs']), '\n'.join(item['rule_ids']),
                         '\n'.join(f"{resource_cells(r.get('resource_id'))[1] or r.get('resource_id')} {r.get('path') or ''}" for r in members),
                         evidence_text(item['evidence_ids']),
                         coverage_display, review['note']])
        table(ws, ["確認ID", "重大度", "元の判定件数", "不明な入力", "確認が必要な理由", "確認する入力・情報と次の行為",
                   "検査結果No", "元JSON参照", "ルールID", "対象と項目", "根拠", "未検査範囲No", "注意"],
              rows, [16, 12, 14, 36, 46, 64, 22, 26, 36, 48, 60, 20, 56],
              wrapped={4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, height_columns={4, 5, 6})
        ws.print_area = f'A1:F{max(1, ws.max_row)}'
        ws.oddFooter.center.text = '詳細根拠・全対応はセルおよび確認関連／未検査関連シートを参照'
        table(wb.create_sheet('確認関連'), ['確認ID', '関連種別', '参照No / グループ', '件数', '元JSON参照'],
              association_rows, [18, 22, 28, 12, 30])
        table(wb.create_sheet('未検査関連'), ['グループ', '未検査範囲No', '元JSON参照'],
              coverage_rows, [24, 20, 30])
    _input_scope_sheets(wb, result.get('input_scope'))
    _full_text_sheet(wb)
    return wb


def _input_scope_sheets(wb, scope):
    if scope is None:
        return
    rows = [['設計承認', scope['design_approval']], ['説明', scope['note']],
            ['台帳メタデータあり', scope['inventory_provided']],
            ['資料全体の項目数', scope['total_items'] if scope['total_items'] is not None else 'UNKNOWN'],
            ['台帳が資料全体を網羅', scope['inventory_complete'] if scope['inventory_complete'] is not None else 'UNKNOWN'],
            ['台帳に記録された項目数', len(scope['items'])],
            ['母資料ID', '\n'.join(scope['source_document_ids'])], ['理由', scope.get('reason', '')]]
    rows.extend([f'{dimension}: {name}', count] for dimension, counts in scope.get('counts', {}).items()
                for name, count in counts.items())
    table(wb.create_sheet('適用範囲'), ['区分', '値'], rows, [55, 100], wrapped={2})
    if scope['items']:
        table(wb.create_sheet('入力追跡'),
              ['項目ID', '分類', '資料上の存在', '入力への表現', '適用範囲', '値の状態', '評価状態',
               '理由', '入力位置', '要求ルール', '観測ルール', '元JSON結果参照', '資料参照', '根拠ID'],
              [[r['id'], r['category'], r['presence'], r['representation'], r['applicability'],
                '\n'.join(r['value_states']), r['evaluation_state'], r['reason'], text(r['bindings']),
                text(r['check_rule_ids']), '\n'.join(r['observed_rule_ids']),
                '\n'.join(f'/results/{i}' for i in r['observed_result_indexes']),
                '\n'.join(r['source_refs']), '\n'.join(r['evidence_ids'])] for r in scope['items']],
              [16, 12, 22, 24, 22, 26, 38, 64, 60, 36, 36, 30, 48, 36], wrapped=set(range(6, 15)))
    if scope['scope_notes']:
        table(wb.create_sheet('未評価方針'), ['ID', '対象', '適用範囲', '理由', '資料参照', '根拠ID'],
              [[r['id'], r['description'], r['applicability'], r['reason'], '\n'.join(r['source_refs']),
                '\n'.join(r['evidence_ids'])] for r in scope['scope_notes']], [16, 65, 24, 90, 48, 36], wrapped={2, 4, 5, 6})


def _summary(ws, result: dict, design: Design | None):
    ws.title = "概要"
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 70
    put(ws, 1, 1, "AWS 設計チェック結果").font = TITLE_FONT
    row = 3
    status = result.get("status", "")
    items = [("処理状態", status), ("設計承認", "NOT_ASSESSED"),
             ("状態の意味", "COMPLETEは処理完了。設計合格・承認・デプロイ可能を意味しません。"),
             ("実行 ID", result.get("run_id", "")),
             ("生成日時", result.get("generated_at", "")),
             ("入力ハッシュ", result.get("input_sha256", ""))]
    if design is not None:
        items[1:1] = [("案件", design.project), ("環境", design.environment),
                      ("アカウント", design.account), ("リージョン", design.region)]
    if result.get("diagnostic"):
        items.append(("診断情報", result["diagnostic"]))
    status_style = ("DDEBF7", "1F4E78") if status == "COMPLETE" else VERDICT_STYLES["FAIL"]
    for label, value in items:
        put(ws, row, 1, label).font = Font(bold=True)
        put(ws, row, 2, value, style=status_style if label == "処理状態" else None, wrap=True)
        row += 1

    row += 1
    put(ws, row, 1, "判定件数").font = SECTION_FONT
    row += 1
    summary = result.get("summary", {})
    for verdict in VERDICT_ORDER:
        put(ws, row, 1, verdict, style=VERDICT_STYLES[verdict])
        put(ws, row, 2, summary.get(verdict, 0)).alignment = Alignment(horizontal="left")
        row += 1
    put(ws, row, 1, "合計").font = Font(bold=True)
    put(ws, row, 2, sum(summary.values())).alignment = Alignment(horizontal="left")
    row += 1
    put(ws, row, 1, "未検査範囲").font = Font(bold=True)
    put(ws, row, 2, len(result.get("coverage", []))).alignment = Alignment(horizontal="left")

    if result.get("review_summary") is not None:
        row += 1
        put(ws, row, 1, "要確認の表示項目数").font = Font(bold=True)
        put(ws, row, 2, result['review_summary']['item_count'])
        row += 1
        put(ws, row, 2, result['review_summary']['note'], wrap=True)

    row += 2
    put(ws, row, 1, "版").font = SECTION_FONT
    row += 1
    versions = dict(result.get("versions") or {})
    manifest = versions.pop("schema_manifest", None) or {}
    for key in ("region", "source", "retrieved_at", "zip_sha256"):
        if key in manifest:
            versions[f"schema_{key}"] = manifest[key]
    for key, value in versions.items():
        put(ws, row, 1, key)
        put(ws, row, 2, text(value), wrap=True)
        row += 1
    row += 1
    put(ws, row, 1, NOTE).font = Font(italic=True, color="595959")
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=2)
    ws.cell(row, 1).alignment = WRAP
    ws.row_dimensions[row].height = 34
    ws.print_options.horizontalCentered = True
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.page_setup.paperSize = ws.PAPERSIZE_A4


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export check results to an Excel workbook")
    parser.add_argument("result", type=Path, help="check result JSON")
    parser.add_argument("--design", type=Path,
                        help="intermediate design JSON; adds resource names, evidence and a design sheet")
    parser.add_argument("--output", required=True, type=Path, help="xlsx file to write")
    args = parser.parse_args(argv)
    try:
        result = json.loads(args.result.read_text(encoding="utf-8"))
        design = (Design.model_validate_json(args.design.read_text(encoding="utf-8"))
                  if args.design else None)
        workbook = build_workbook(result, design)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(args.output)
    except Exception as exc:
        print(f"FAILED: {exc}")
        return 2
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
