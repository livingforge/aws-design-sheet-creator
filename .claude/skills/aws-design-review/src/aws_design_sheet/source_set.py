"""Source set: which ARP4-parsed documents a design may cite, and which are older versions.

ARP4 imports every original below its sources folder, so drafts, copies and archived
versions sit beside the current documents. `scan` proposes version families from each
document's own ID and version cells, then from file names; a person the user names
approves the set; `check` refuses a set that no longer matches ARP4 and design sources
that cite superseded or excluded documents. Statuses are decided by people, never here.
"""
import argparse
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from .delegation import Basis, InputError as DelegationError, is_agent, person_name


class InputError(ValueError):
    pass


Status = Literal['CURRENT', 'SUPERSEDED', 'REFERENCE', 'EXCLUDED', 'UNDECIDED']
CITABLE = {'CURRENT', 'REFERENCE'}
# Labels of a document's own ID and version, compared after norm().
CODE_LABELS = {'文書id', '文書番号', '文書コード', '文書no', 'ドキュメントid', 'ドキュメント番号', '資料番号', '管理番号',
               'documentid', 'documentno', 'documentnumber', 'docid', 'docno'}
VERSION_LABELS = {'版', '版数', '版番号', '改版', '改訂版', 'バージョン', 'version', 'ver', 'rev', 'revision'}
STATUS_WORDS = {'draft', 'ドラフト', '案', '素案', 'final', '確定', '確定版', '最新', '最新版', 'latest', 'old', '旧', '旧版',
                'copy', 'コピー', 'fix', '修正', '修正版', '改', '改訂', 'wip', 'review', 'レビュー', 'レビュー済', 'ver', 'rev', 'v'}
ARCHIVE_FOLDERS = {'old', 'archive', 'archives', 'archived', '旧', '旧版', '過去', '過去版', 'backup', 'bk', 'bak', 'history',
                   '履歴', 'versions', 'version', 'obsolete', '廃止', '退避'}
DOTTED = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){1,3})(?![\d.])')
PREFIXED = re.compile(r'(?:第\s*(\d{1,3})\s*版|(?<![a-z])(?:ver|rev|v)\.?\s*(\d{1,3}(?:\.\d{1,3}){0,3})(?![\d.]))', re.I)
DATE = re.compile(r'(?<!\d)(20\d{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)')
# A document whose folder, role cell or title holds one of these words may be a proposal, estimate or
# other reference rather than a design basis: its single or newest version goes to the approver
# as UNDECIDED (POSSIBLY_REFERENCE) instead of CURRENT. Matched as substrings after norm().
REFERENCE_WORDS = ('参考', '提案', '見積', '受注前', '他社', '他案件', 'proposal', 'reference', 'estimate', 'quotation', 'rfp', 'rfi',
                   # Working material that sits beside design documents but does not decide the design. Minutes are left out:
                   # they often record the decisions a design rests on.
                   '課題管理', '課題一覧', '検討メモ', '検討資料', '作業用', '作業メモ',
                   '製品資料', '製品カタログ', '製品マニュアル', 'キャプチャ', 'スクリーンショット', 'screenshot', 'datasheet', 'whitepaper')
ROLE_LABELS = {'種別', '文書種別', '資料種別', '位置付け', '位置づけ', '文書区分', '資料区分', '分類', '用途',
               'documenttype', 'doctype', 'category', 'purpose'}
COVER_CELLS = 40
COPY_MARK = re.compile(r'[(（]\s*\d{1,2}\s*[)）]|\s*-\s*コピー|\s*のコピー|\bcopy(?:\s*of)?\b', re.I)
# What kind of document it is, from the first of its role cell, title, file name and folders (innermost first) that holds
# one of these words; the kinds are tried in this order. ASCII words match at the start of a word only.
Kind = Literal['MINUTES', 'REQUIREMENTS', 'ARCHITECTURE', 'OPERATIONS', 'TEST', 'PROJECT', 'APPLICATION', 'DESIGN']
KIND_WORDS = (
    ('MINUTES', ('議事録', '議事メモ', '打合せ', '打ち合わせ', 'ミーティング', 'minutes')),
    ('REQUIREMENTS', ('要件', '要求仕様', '要求定義', 'requirement')),
    ('ARCHITECTURE', ('方式', '基盤', 'インフラ', '構成図', 'システム構成', '環境構成', 'ネットワーク', 'アーキテクチャ', 'パラメータシート',
                      'パラメーターシート', '環境定義', 'セキュリティ設計', 'architecture', 'infrastructure', 'network')),
    ('OPERATIONS', ('運用', '監視', '保守', 'バックアップ', '移行', '障害対応', 'operation', 'runbook')),
    ('TEST', ('テスト', '試験', 'test')),
    ('PROJECT', ('計画書', 'wbs', '体制', 'スケジュール', '工程表', '進捗')),
    ('APPLICATION', ('画面', '帳票', 'テーブル', 'データ項目', 'コード定義', 'メッセージ定義', '機能一覧', '機能仕様', 'モジュール', '処理仕様',
                     '共通部品', 'プログラム', 'クラス図', 'er図', 'インターフェース仕様', 'インタフェース仕様')),
    ('DESIGN', ('設計', 'design', 'spec')),
)
KIND_PATTERNS = [(kind, [(w, re.compile((r'(?<![a-z])' if w.isascii() else '') + re.escape(w))) for w in words]) for kind, words in KIND_WORDS]
# Kinds that hold what an AWS design rests on whatever their cells say.
PRIMARY_KINDS = {'MINUTES', 'REQUIREMENTS', 'ARCHITECTURE', 'OPERATIONS'}
# Words of infrastructure in a cell; a document with INFRA_CELLS such cells, or one AWS service named, is PRIMARY.
INFRA_WORDS = re.compile(r'(?<![A-Za-z])(?:VPC|CIDR|RPO|RTO|AWS|VPN|DNS|WAF|SSO|IAM)(?![A-Za-z])|サブネット|ネットワーク|冗長|可用性|バックアップ|'
                         r'監視|暗号化|セキュリティグループ|ファイアウォール|ロードバランサ|サーバ|インスタンス|リージョン|アベイラビリティ|'
                         r'クラウド|オンプレ|閉域|専用線|証明書|認証基盤|非機能|災害対策|稼働率|ログ保[管存]')
INFRA_CELLS = 3


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ReferenceHint(Strict):
    basis: Literal['FOLDER', 'ROLE', 'TITLE']
    word: str
    text: str
    cell: str | None = None


class KindHint(Strict):
    basis: Literal['ROLE', 'TITLE', 'FILE_NAME', 'FOLDER']
    word: str
    text: str
    cell: str | None = None


class Signals(Strict):
    title: str | None = None
    title_cell: str | None = None
    role: str | None = None
    role_cell: str | None = None
    reference: list[ReferenceHint] = []
    code: str | None = None
    code_cell: str | None = None
    version: str | None = None
    version_basis: Literal['CONTENT', 'FILE_NAME'] | None = None
    version_cell: str | None = None
    archive_folder: bool = False
    kind: Kind | None = None
    kind_hint: KindHint | None = None
    # Distinct AWS services its cells and drawings name, and cells holding an infrastructure word.
    aws_services: int = 0
    infra_cells: int = 0


class Entry(Strict):
    document_id: str
    source_path: str
    source_sha256: str
    extraction_sha256: str
    family: str
    family_basis: Literal['DOCUMENT_CODE', 'FILE_NAME']
    signals: Signals
    status: Status
    reason: str
    related: str | None = None
    # DRAFT: a draft settled an UNDECIDED document by rule (draft-mode.md); a person never did.
    decided: Literal['PROPOSED', 'SET', 'DRAFT'] = 'PROPOSED'
    # PRIMARY documents hold what an AWS design rests on; PERIPHERAL ones (screens, tables, plans, tests) are read
    # when a value is looked for. Advice for reading, never a status: both stay citable when CURRENT.
    relevance: Literal['PRIMARY', 'PERIPHERAL'] = 'PRIMARY'


class Approval(Strict):
    approver: str
    approved_at: str
    proposal_sha256: str
    # Set only when an agent approved under a delegation policy; a person's approval has none.
    delegation: Basis | None = None
    # A draft set: run all made it in draft mode, settling UNDECIDED documents by rule. No one approved it.
    draft: bool = False


class SourceSet(Strict):
    schema_version: Literal['1']
    kind: Literal['proposal', 'approved']
    documents: list[Entry]
    issues: list[dict] = []
    approval: Approval | None = None


def sha(raw):return hashlib.sha256(raw).hexdigest()


def norm(text):
    return re.sub(r'[\s■□●◆※・:：\-_/()（）\[\]【】]', '', unicodedata.normalize('NFKC', str(text)).lower())


def version_key(text):
    """Comparable key, or None. Dates and dotted numbers are never compared with each other."""
    if (m := DATE.search(text)):return ('date', tuple(int(g) for g in m.groups()))
    if (m := PREFIXED.search(text)):return ('number', tuple(int(x) for x in (m.group(1) or m.group(2)).split('.')))
    if (m := DOTTED.search(text)):return ('number', tuple(int(x) for x in m.group(1).split('.')))
    return None


def column(letters):
    n = 0
    for ch in letters:n = n * 26 + ord(ch) - 64
    return n


def content_signals(extraction):
    """The document's own ID, version, title and role: the cell right of a known label, else one version in the title cells."""
    signals = {}
    for number, sheet in enumerate(extraction.get('sheets', []), 1):
        cells = [c for c in sheet.get('cells', []) if isinstance(c.get('value'), (str, int, float)) and str(c['value']).strip()]
        at = {}
        for c in cells:
            m = re.fullmatch(r'([A-Z]+)(\d+)', c.get('address', ''))
            if m:at[(column(m.group(1)), int(m.group(2)))] = c
        if number == 1 and cells and 'title' not in signals:
            signals['title'], signals['title_cell'] = clip(cells[0]['value']), f"s{number}-{cells[0]['address']}"
        for i, c in enumerate(cells):
            label = norm(c['value'])
            m = re.fullmatch(r'([A-Z]+)(\d+)', c.get('address', ''))
            if not m or (label not in CODE_LABELS and label not in VERSION_LABELS and label not in ROLE_LABELS):continue
            right = at.get((column(m.group(1)) + 1, int(m.group(2))))
            if right is None:continue
            # A role is read from the cover only: 種別 is also a common column heading in the body's tables.
            if label in ROLE_LABELS and 'role' not in signals and number == 1 and i < COVER_CELLS:
                signals['role'], signals['role_cell'] = clip(right['value']), f"s{number}-{right['address']}"
            if label in CODE_LABELS and 'code' not in signals:
                signals['code'], signals['code_cell'] = str(right['value']).strip(), f"s{number}-{right['address']}"
            if label in VERSION_LABELS and 'version' not in signals and version_key(str(right['value'])):
                signals['version'], signals['version_cell'] = str(right['value']).strip(), f"s{number}-{right['address']}"
        if number == 1 and 'version' not in signals:
            found = {}
            for c in cells[:10]:
                text = str(c['value'])
                key = version_key(DATE.sub('', text))
                if key:found.setdefault(key, (text.strip(), f"s{number}-{c['address']}"))
            if len(found) == 1:
                signals['version'], signals['version_cell'] = next(iter(found.values()))
    if 'version' in signals:signals['version_basis'] = 'CONTENT'
    hints = [{'basis': basis, 'word': word, 'text': signals[key], 'cell': signals[key + '_cell']}
             for basis, key in (('ROLE', 'role'), ('TITLE', 'title')) if signals.get(key) and (word := reference_word(signals[key]))]
    if hints:signals['reference'] = hints
    return signals


def clip(text, limit=80):
    text = re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(text))).strip()
    return text if len(text) <= limit else text[:limit - 1] + '…'


def reference_word(text):
    """The first reference word the text holds, or None."""
    plain = norm(text)
    return next((w for w in REFERENCE_WORDS if w in plain), None)


def name_signals(document_id):
    path = PurePosixPath(document_id)
    stem = unicodedata.normalize('NFKC', path.stem)
    signals = {'archive_folder': any(norm(p) in ARCHIVE_FOLDERS or version_key(p) for p in path.parts[:-1])}
    folders = [{'basis': 'FOLDER', 'word': word, 'text': p} for p in path.parts[:-1] if (word := reference_word(p))]
    if folders:signals['reference'] = folders[:1]
    key = version_key(stem)
    if key:signals.update(version=stem, version_basis='FILE_NAME')
    base = COPY_MARK.sub(' ', stem.lower())
    base = DATE.sub(' ', base);base = PREFIXED.sub(' ', base);base = DOTTED.sub(' ', base)
    tokens = [t for t in re.split(r'[\s\-_.()（）\[\]【】]+', base) if t and t not in STATUS_WORDS and not t.isdigit()]
    return signals, '-'.join(tokens) + path.suffix.lower()


def document_kind(document_id, signals):
    """(kind, hint) from the first of the role cell, title, file name and folders that names a kind, or (None, None)."""
    path = PurePosixPath(document_id)
    texts = [('ROLE', signals.get('role'), signals.get('role_cell')), ('TITLE', signals.get('title'), signals.get('title_cell')),
             ('FILE_NAME', path.stem, None)] + [('FOLDER', p, None) for p in reversed(path.parts[:-1])]
    for basis, text, cell in texts:
        if not text:continue
        plain = unicodedata.normalize('NFKC', str(text)).lower()
        for kind, patterns in KIND_PATTERNS:
            for word, pattern in patterns:
                if pattern.search(plain):return kind, KindHint(basis=basis, word=word, text=clip(text), cell=cell)
    return None, None


def infra_signals(extraction):
    """(distinct AWS services named, cells holding an infrastructure word) over a document's cells and drawing texts."""
    from .service_mentions import detect
    texts = [t for _, t in cell_texts(extraction)]
    for sheet in extraction.get('sheets', []) or []:
        for drawing in sheet.get('drawings', []) or []:
            texts += [str(drawing[k]) for k in ('text', 'description') if drawing.get(k)]
    # One pass over the joined text: the service dictionary has hundreds of patterns, a document thousands of cells.
    return len(detect('\n'.join(texts))), sum(1 for t in texts if INFRA_WORDS.search(t))


def relevance(signals):
    if signals.kind in PRIMARY_KINDS or signals.aws_services or signals.infra_cells >= INFRA_CELLS:return 'PRIMARY'
    return 'PERIPHERAL'


def read_arp(root):
    """Adopted documents with their records; issues about originals and pending re-imports."""
    import yaml
    base = root / '.arp' / 'documents'
    if not base.is_dir():raise InputError('NO_ARP_DOCUMENTS: .arp/documents not found below the ARP root')
    documents, issues = [], []
    for record_path in sorted(base.rglob('document.yml')):
        folder = record_path.parent
        if not (folder / 'extraction.json').is_file():continue
        record = yaml.safe_load(record_path.read_bytes()) or {}
        document_id = record.get('document_id')
        if not isinstance(document_id, str) or folder.relative_to(base).as_posix() != document_id:continue
        extraction_raw = (folder / 'extraction.json').read_bytes()
        source = record.get('source') or {}
        if sha(extraction_raw) != record.get('extraction'):issues.append({'code': 'EXTRACTION_MISMATCH', 'document': document_id})
        original = root / str(source.get('path', ''))
        if not source.get('path') or not original.is_file():issues.append({'code': 'SOURCE_MISSING', 'document': document_id})
        elif sha(original.read_bytes()) != source.get('sha256'):issues.append({'code': 'SOURCE_CHANGED', 'document': document_id})
        if (root / '.arp' / 'changes' / document_id / 'document.yml').is_file():
            issues.append({'code': 'REIMPORT_PENDING', 'document': document_id})
        documents.append({'document_id': document_id, 'source_path': str(source.get('path', '')),
                          'source_sha256': str(source.get('sha256', '')), 'extraction_sha256': sha(extraction_raw),
                          'extraction': json.loads(extraction_raw)})
    changes = root / '.arp' / 'changes'
    adopted = {d['document_id'] for d in documents}
    if changes.is_dir():
        for record_path in sorted(changes.rglob('document.yml')):
            document_id = record_path.parent.relative_to(changes).as_posix()
            if (record_path.parent / 'extraction.json').is_file() and document_id not in adopted:
                issues.append({'code': 'NOT_ADOPTED', 'document': document_id})
    return documents, issues


def propose(documents):
    """One entry per document; the newest distinct version of each family is proposed CURRENT."""
    entries, families = [], {}
    for d in documents:
        named, base = name_signals(d['document_id'])
        found = content_signals(d['extraction'])
        kind, hint = document_kind(d['document_id'], found)
        services, infra = infra_signals(d['extraction'])
        signals = Signals(**{**named, **found, 'archive_folder': named['archive_folder'],
                             'reference': found.get('reference', []) + named.get('reference', [])},
                          kind=kind, kind_hint=hint, aws_services=services, infra_cells=infra)
        family, basis = (('code:' + norm(signals.code), 'DOCUMENT_CODE') if signals.code else ('name:' + base, 'FILE_NAME'))
        entry = Entry(document_id=d['document_id'], source_path=d['source_path'], source_sha256=d['source_sha256'],
                      extraction_sha256=d['extraction_sha256'], family=family, family_basis=basis, signals=signals,
                      status='UNDECIDED', reason='', relevance=relevance(signals))
        entries.append(entry);families.setdefault(family, []).append(entry)
    for members in families.values():
        by_content = {}
        for e in members:by_content.setdefault(e.source_sha256, []).append(e)
        distinct = []
        for same in by_content.values():
            keep = min(same, key=lambda e: (e.signals.archive_folder, len(e.document_id), e.document_id))
            distinct.append(keep)
            for e in same:
                if e is not keep:e.status, e.reason, e.related = 'EXCLUDED', 'DUPLICATE_OF', keep.document_id
        if len(distinct) == 1:
            e = distinct[0]
            e.status, e.reason = ('UNDECIDED', 'ARCHIVE_FOLDER') if e.signals.archive_folder else ('CURRENT', 'ONLY_VERSION')
            continue
        keys = {e.document_id: version_key(e.signals.version or '') for e in distinct}
        kinds = {k[0] for k in keys.values() if k}
        if None in keys.values() or len(kinds) != 1 or len(set(keys.values())) != len(distinct):
            for e in distinct:e.status, e.reason = 'UNDECIDED', 'VERSION_UNORDERED'
            continue
        newest = max(distinct, key=lambda e: keys[e.document_id])
        for e in distinct:
            if e is not newest:e.status, e.reason, e.related = 'SUPERSEDED', 'OLDER_VERSION', newest.document_id
        newest.status, newest.reason = ('UNDECIDED', 'NEWEST_IN_ARCHIVE_FOLDER') if newest.signals.archive_folder else ('CURRENT', 'NEWEST_VERSION')
    for e in entries:
        # Versions say which copy is newest, not whether the document is a design basis at all.
        if e.status == 'CURRENT' and e.signals.reference:e.status, e.reason = 'UNDECIDED', 'POSSIBLY_REFERENCE'
    return sorted(entries, key=lambda e: (e.family, e.document_id))


def blocking(issues, statuses):
    """Problems with an original or its parse matter only for documents a design may cite."""
    errors, warnings = [], []
    for issue in issues:
        (errors if statuses.get(issue['document'], 'CURRENT') in CITABLE and issue['code'] != 'NOT_ADOPTED' else warnings).append(issue)
    return errors, warnings


def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def scan(root):
    documents, issues = read_arp(root)
    return SourceSet(schema_version='1', kind='proposal', documents=propose(documents), issues=issues)


def approve(root, proposal_raw, approver, settings, *, now=None, delegation=None):
    """Approve the fresh scan exactly as proposed, with the approver's explicit status settings.

    A person approves by name; an agent approves only with a delegation basis and no settings of its own."""
    if delegation is None:
        try:approver = person_name(approver)
        except DelegationError as exc:raise InputError(str(exc)) from None
    elif not is_agent(approver) or settings:raise InputError('DELEGATED_APPROVAL: an agent approves as proposed, under an agent name')
    fresh = scan(root)
    if sha(dump(fresh.model_dump())) != sha(dump(SourceSet.model_validate_json(proposal_raw).model_dump())):
        raise InputError('PROPOSAL_STALE: the proposal differs from a fresh scan of ARP4; scan again and show the new proposal')
    entries = {e.document_id: e for e in fresh.documents}
    for document_id, status in settings.items():
        if document_id not in entries:raise InputError(f'UNKNOWN_DOCUMENT: {document_id}')
        if status not in ('CURRENT', 'SUPERSEDED', 'REFERENCE', 'EXCLUDED'):raise InputError(f'INVALID_STATUS: {status}')
        entries[document_id].status, entries[document_id].decided = status, 'SET'
    undecided = sorted(d for d, e in entries.items() if e.status == 'UNDECIDED')
    if undecided:raise InputError('UNDECIDED_DOCUMENTS: ' + ', '.join(undecided))
    errors, _ = blocking(fresh.issues, {d: e.status for d, e in entries.items()})
    if errors:raise InputError('SOURCE_ISSUES: ' + ', '.join(f"{i['code']} {i['document']}" for i in errors))
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    return SourceSet(schema_version='1', kind='approved', documents=list(entries.values()), issues=fresh.issues,
                     approval=Approval(approver=approver.strip(), approved_at=stamp, proposal_sha256=sha(proposal_raw), delegation=delegation))


# How a draft settles each reason a document is UNDECIDED (draft-mode.md 3.1); a version family whose order is unknown
# keeps every member CURRENT until a person picks one.
DRAFT_RULES = {'POSSIBLY_REFERENCE': 'REFERENCE', 'ARCHIVE_FOLDER': 'REFERENCE', 'NEWEST_IN_ARCHIVE_FOLDER': 'CURRENT', 'VERSION_UNORDERED': 'CURRENT'}


def approve_draft(root, proposal_raw, *, now=None):
    """A draft set from the fresh scan: UNDECIDED documents settled by DRAFT_RULES, and a citable document whose original
    or parse has a problem EXCLUDED so the draft never reads a stale parse. Recorded under DRAFT_AGENT, never as approval."""
    fresh = scan(root)
    if sha(dump(fresh.model_dump())) != sha(dump(SourceSet.model_validate_json(proposal_raw).model_dump())):
        raise InputError('PROPOSAL_STALE: the proposal differs from a fresh scan of ARP4; scan again')
    return draft_from(fresh, sha(proposal_raw), now=now)


def draft_from(fresh, proposal_sha256, *, now=None):
    """The draft set of one scan. `run all` scans and settles in one step with this, so that ARP4 changing between a
    scan and its approval can never stop a draft."""
    from .delegation import DRAFT_AGENT
    for e in fresh.documents:
        if e.status == 'UNDECIDED':
            if e.reason not in DRAFT_RULES:raise InputError(f'NO_DRAFT_RULE: {e.reason}')
            e.status, e.decided = DRAFT_RULES[e.reason], 'DRAFT'
    errors, _ = blocking(fresh.issues, {e.document_id: e.status for e in fresh.documents})
    troubled = {i['document'] for i in errors}
    for e in fresh.documents:
        if e.document_id in troubled:e.status, e.decided = 'EXCLUDED', 'DRAFT'
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    return SourceSet(schema_version='1', kind='approved', documents=fresh.documents, issues=fresh.issues,
                     approval=Approval(approver=DRAFT_AGENT, approved_at=stamp, proposal_sha256=proposal_sha256, draft=True))


def set_changes(before, after):
    """What differs between two sets, by document ID: documents that came, went, were imported again or changed status."""
    old = {e.document_id: e for e in before.documents};new = {e.document_id: e for e in after.documents}
    both = sorted(set(old) & set(new))
    found = {'added': sorted(set(new) - set(old)), 'removed': sorted(set(old) - set(new)),
             'imported_again': [d for d in both if (old[d].source_sha256, old[d].extraction_sha256) != (new[d].source_sha256, new[d].extraction_sha256)],
             'status_changed': [{'document': d, 'from': old[d].status, 'to': new[d].status} for d in both if old[d].status != new[d].status]}
    return {k: v for k, v in found.items() if v}


def load_approved(raw):
    approved = SourceSet.model_validate_json(raw)
    if approved.kind != 'approved' or approved.approval is None:raise InputError('SOURCE_SET_NOT_APPROVED')
    return approved


def require_current(raw, document_id, source_sha256, extraction_sha256):
    """For one ARP4 document used directly (an external sheet): it must be CURRENT and unchanged."""
    entry = next((e for e in load_approved(raw).documents if e.document_id == document_id), None)
    if entry is None:raise InputError(f'UNLISTED_DOCUMENT: {document_id} is not in the source set')
    if entry.status != 'CURRENT':raise InputError(f'NOT_CURRENT: {document_id} is {entry.status} in the source set')
    if (entry.source_sha256, entry.extraction_sha256) != (source_sha256, extraction_sha256):
        raise InputError(f'DOCUMENT_CHANGED: {document_id} differs from the approved source set')


def design_citations(design):
    """Declared sources and how many design objects cite each one."""
    sources = [s for s in design.get('sources', []) if isinstance(s, dict)]
    counts = {s.get('id'): 0 for s in sources}

    def walk(value, top=False):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'sources' and not top and isinstance(child, list):
                    for sid in child:
                        if sid in counts:counts[sid] += 1
                else:walk(child)
        elif isinstance(value, list):
            for child in value:walk(child)
    for key, value in design.items():
        if key != 'sources':walk(value)
    return [(s.get('id'), str(s.get('locator', '')), counts[s.get('id')]) for s in sources]


# Values a design copies from documents; quantities with units are compared as written.
DESIGN_TOKENS = [
    ('CIDR', re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\d/])')),
    ('IP', re.compile(r'(?<![\d./])(?:\d{1,3}\.){3}\d{1,3}(?![\d./])')),
    ('ARN', re.compile(r'arn:aws[a-z-]*:[^\s,，、。）)"\']+')),
    ('INSTANCE_TYPE', re.compile(r'(?<![\w.])(?:db\.|cache\.)?[a-z][a-z0-9-]*\d[a-z0-9-]*\.(?:nano|micro|small|medium|large|\d*xlarge|metal)(?![\w.])')),
    ('QUANTITY', re.compile(r'(?<![\d.,])(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\s?(?:GiB|GB|MiB|MB|TiB|TB|ms|秒|分|時間|日|か月|ヶ月|年|vCPU|ACU|%)', re.I)),
]
CALENDAR_YEAR = re.compile(r'(?:19|20)\d{2}年')
MATCHED_IN_DESIGN = {'CIDR', 'IP', 'ARN', 'INSTANCE_TYPE'}


def tokens(text):
    text = unicodedata.normalize('NFKC', str(text))
    found = set()
    for kind, pattern in DESIGN_TOKENS:
        for m in pattern.finditer(text):
            value = re.sub(r'[\s,]', '', m.group(0))
            if not (kind == 'QUANTITY' and CALENDAR_YEAR.fullmatch(value)):found.add((kind, value))
    return found


def cell_texts(extraction):
    for number, sheet in enumerate(extraction.get('sheets', []), 1):
        for c in sheet.get('cells', []):
            value = c.get('value')
            if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value).strip():
                yield f"s{number}-{c.get('address')}", re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(value))).strip()


def version_diff(documents, entries):
    """Per SUPERSEDED document: cell texts removed and added against its newer document, and design values found only in old versions."""
    texts = {d['document_id']: list(cell_texts(d['extraction'])) for d in documents}
    current = set()
    for document_id, entry in entries.items():
        if entry.status in CITABLE and document_id in texts:
            for _, text in texts[document_id]:current |= tokens(text)
    pairs, old_only = [], {}
    for document_id, entry in sorted(entries.items()):
        if entry.status != 'SUPERSEDED' or document_id not in texts:continue
        for cid, text in texts[document_id]:
            for token in tokens(text) - current:old_only.setdefault(token, []).append(f'{document_id}#{cid}')
        newer = entry.related
        if newer not in texts:continue
        new_set = {t for _, t in texts[newer]};old_set = {t for _, t in texts[document_id]}
        old_values = set().union(*(tokens(t) for t in old_set));new_values = set().union(*(tokens(t) for t in new_set))
        removed = [{'cell': cid, 'text': t, 'values': sorted(v for _, v in tokens(t) & (old_values - new_values))}
                   for cid, t in texts[document_id] if t not in new_set]
        added = [{'cell': cid, 'text': t, 'values': sorted(v for _, v in tokens(t) & (new_values - old_values))}
                 for cid, t in texts[newer] if t not in old_set]
        pairs.append({'document': document_id, 'newer': newer, 'removed': removed, 'added': added,
                      'removed_values': sorted(v for _, v in old_values - new_values),
                      'added_values': sorted(v for _, v in new_values - old_values)})
    return pairs, {token: sorted(set(where)) for token, where in old_only.items()}


def design_values(design):
    """Scalar strings under setting values, with their input pointers."""
    found = []

    def walk(value, pointer, inside):
        if isinstance(value, dict):
            for key, child in value.items():walk(child, f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}", inside or key == 'value')
        elif isinstance(value, list):
            for i, child in enumerate(value):walk(child, f'{pointer}/{i}', inside)
        elif inside and isinstance(value, str):found.append((pointer, value))
    for key in ('resources', 'environments'):walk(design.get(key), '/' + key, False)
    return found


def stale_values(documents, entries, design):
    _, old_only = version_diff(documents, entries)
    stale = []
    for pointer, value in design_values(design):
        for kind, token in sorted(tokens(value)):
            if kind in MATCHED_IN_DESIGN and (kind, token) in old_only:
                stale.append({'code': 'STALE_VALUE_IN_DESIGN', 'pointer': pointer, 'kind': kind, 'value': token, 'found_in': old_only[(kind, token)]})
    return stale


def check(root, set_raw, design=None):
    approved = load_approved(set_raw)
    documents, issues = read_arp(root)
    entries = {e.document_id: e for e in approved.documents}
    statuses = {d: e.status for d, e in entries.items()}
    errors, warnings = blocking(issues, statuses)
    now = {d['document_id']: d for d in documents}
    for document_id, entry in entries.items():
        bucket = errors if entry.status in CITABLE else warnings
        if document_id not in now:bucket.append({'code': 'DOCUMENT_REMOVED', 'document': document_id})
        elif (now[document_id]['source_sha256'], now[document_id]['extraction_sha256']) != (entry.source_sha256, entry.extraction_sha256):
            bucket.append({'code': 'DOCUMENT_CHANGED', 'document': document_id})
    for document_id in sorted(set(now) - set(entries)):
        errors.append({'code': 'UNLISTED_DOCUMENT', 'document': document_id})
    families = {}
    for e in approved.documents:
        if e.status == 'CURRENT':families.setdefault(e.family, []).append(e.document_id)
    for family, ids in sorted(families.items()):
        if len(ids) > 1:warnings.append({'code': 'MULTIPLE_CURRENT', 'family': family, 'documents': sorted(ids)})
    citations, cited = [], set()
    if design is not None:
        for source_id, locator, count in design_citations(design):
            document_id = locator.split('#', 1)[0]
            entry = entries.get(document_id)
            row = {'source': source_id, 'document': document_id if entry else None, 'status': entry.status if entry else None, 'cited_by': count}
            citations.append(row)
            if entry is None:warnings.append({'code': 'SOURCE_NOT_IN_SET', 'source': source_id})
            elif entry.status in ('SUPERSEDED', 'EXCLUDED'):
                errors.append({'code': 'CITES_' + entry.status, 'source': source_id, 'document': document_id, 'newer': entry.related})
            elif entry.status == 'REFERENCE':warnings.append({'code': 'CITES_REFERENCE', 'source': source_id, 'document': document_id})
            if entry:cited.add(document_id)
        warnings.extend(stale_values(documents, entries, design))
    counts = {}
    for e in approved.documents:counts[e.status] = counts.get(e.status, 0) + 1
    report = {'status': 'FAIL' if errors else 'PASS', 'approval': approved.approval.model_dump(), 'documents': counts,
              'errors': errors, 'warnings': warnings}
    if design is not None:
        report['citations'] = citations
        report['current_not_cited'] = sorted(d for d, e in entries.items() if e.status == 'CURRENT' and d not in cited)
    return report


def markdown(source_set):
    """Table for the person who approves the set: one row per document, grouped by family, with its title and role."""
    lines = ['| 系列 | 文書 | 表題・位置付け | 版（根拠） | 状態 | 理由 | 関連度 |', '|---|---|---|---|---|---|---|']
    cell = lambda text: str(text).replace('|', '｜')
    for e in source_set.documents:
        version = e.signals.version or '—'
        basis = {'CONTENT': f'本文 {e.signals.version_cell}', 'FILE_NAME': 'ファイル名'}.get(e.signals.version_basis, '')
        family = f'{e.signals.code}（文書ID {e.signals.code_cell}）' if e.family_basis == 'DOCUMENT_CODE' else e.family.split(':', 1)[1] + '（ファイル名）'
        reason = e.reason + (f' → {e.related}' if e.related else '') + {'SET': '（承認者が指定）', 'DRAFT': '（下書きの規則で決定）'}.get(e.decided, '')
        if e.reason == 'POSSIBLY_REFERENCE':reason += '（' + reference_note(e) + '）'
        about = '<br>'.join(cell(x) for x in (e.signals.title, f'位置付け：{e.signals.role}' if e.signals.role else None) if x) or '—'
        lines.append(f"| {family} | {e.document_id} | {about} | {version}（{basis}） | {e.status} | {cell(reason)} | {relevance_note(e)} |".replace('（）', ''))
    for issue in source_set.issues:lines.append(f"\n- {issue['code']}: {issue['document']}")
    return '\n'.join(lines) + '\n'


KINDS_JA = {'MINUTES': '議事録', 'REQUIREMENTS': '要件', 'ARCHITECTURE': '方式・構成', 'OPERATIONS': '運用・移行', 'TEST': 'テスト',
            'PROJECT': '計画・体制', 'APPLICATION': '画面・帳票・データ・処理', 'DESIGN': '設計書'}


def relevance_note(entry):
    """The relevance with what it rests on: the kind and its word, AWS services named and infrastructure cells."""
    s = entry.signals
    where = {'ROLE': '位置付け', 'TITLE': '表題', 'FILE_NAME': 'ファイル名', 'FOLDER': 'フォルダ'}
    kind = f"{KINDS_JA[s.kind]}（{where[s.kind_hint.basis]}「{s.kind_hint.word}」）" if s.kind and s.kind_hint else '種類不明'
    return f'{entry.relevance}：{kind}、AWSサービス {s.aws_services}、基盤の語のセル {s.infra_cells}'


def reference_note(entry):
    """Why a document may be a reference, for the approver."""
    where = {'FOLDER': 'フォルダ', 'ROLE': '位置付け', 'TITLE': '表題'}
    found = '、'.join(f"{where[h.basis]}{' ' + h.cell if h.cell else ''}「{h.word}」" for h in entry.signals.reference)
    return f'参考資料・提案書・課題表・作業用資料・製品資料などの可能性：{found}。設計の根拠なら CURRENT、そうでなければ REFERENCE か EXCLUDED を --set で指定'


def render_diff(report):
    """For the reviewer: changed design values per version pair, then values no current document still holds."""
    lines = ['# 版の差分', '']
    for pair in report['pairs']:
        lines += [f"## {pair['document']} → {pair['newer']}", '',
                  f"削除されたセル {len(pair['removed'])}件・追加されたセル {len(pair['added'])}件。",
                  f"削除された設計値：{'、'.join(pair['removed_values']) or 'なし'}",
                  f"追加された設計値：{'、'.join(pair['added_values']) or 'なし'}", '']
    lines += ['## 旧版にだけある設計値', '']
    if report['old_only_values']:
        lines += ['| 種類 | 値 | 記載箇所 |', '|---|---|---|']
        lines += [f"| {v['kind']} | {v['value']} | {'、'.join(v['found_in'])} |" for v in report['old_only_values']]
    else:lines.append('なし。')
    lines += ['', '現行・参考文書のどれにもない値。設計に残っていれば `check --design` が STALE_VALUE_IN_DESIGN として警告する。']
    return '\n'.join(lines) + '\n'


def cells(root, set_raw, document=None, sheet=None, grep=None):
    """What an author reads and cites: the cells and drawing texts of the documents a design may cite, each with the
    ID a source's locator names. Without a document, the citable documents; with `grep`, the cells holding a text."""
    from .diagram_ledger import element_texts
    approved = load_approved(set_raw)
    entries = {e.document_id: e for e in approved.documents}
    documents = {d['document_id']: d for d in read_arp(root)[0]}
    if document is not None:
        entry = entries.get(document)
        if entry is None or document not in documents:
            raise InputError(f'UNLISTED_DOCUMENT: {document} is not in the source set; run this command without --document for the documents a design may cite')
        if entry.status not in CITABLE:
            raise InputError(f'NOT_CITABLE: {document} is {entry.status}; a design reads and cites CURRENT documents' + (f' (newer: {entry.related})' if entry.related else ''))
    wanted = [document] if document else sorted(d for d, e in entries.items() if e.status in CITABLE and d in documents)
    plain = lambda text:unicodedata.normalize('NFKC', text).casefold()
    lines = []
    if document is None and grep is None:
        lines = ['# 設計が読んで引用できる文書（CURRENT から読む。PRIMARY が先）。--document 文書ID で全セル、--grep 語 で語を含むセルを出す', '']
        order = sorted(wanted, key=lambda d:(entries[d].status != 'CURRENT', entries[d].relevance != 'PRIMARY', d))
        for d in order:
            extraction = documents[d]['extraction']
            lines.append(f"{d}\t{entries[d].status}\t{entries[d].relevance}\tsheets={len(extraction.get('sheets', []) or [])}"
                         f"\tcells={sum(1 for _ in cell_texts(extraction))}\tdrawings={sum(1 for _ in element_texts(extraction))}")
        return lines
    for d in wanted:
        extraction = documents[d]['extraction']
        names = {n: s.get('name', '') for n, s in enumerate(extraction.get('sheets', []) or [], 1)}
        rows = [(cid, text) for cid, text in list(cell_texts(extraction)) + list(element_texts(extraction))
                if (sheet is None or cid.startswith(f's{sheet}-')) and (grep is None or plain(grep) in plain(text))]
        if grep is not None:
            lines += [f'{d}#{cid}\t{text}' for cid, text in rows];continue
        lines += [f'# {d}（{entries[d].status}、{entries[d].relevance}）', f'# 引用の書き方：sources の locator に {d}#<ID>（例 {d}#{rows[0][0] if rows else "s1-A1"}）。'
                  'セルは s<シート>-<番地>、図形は s<シート>-d<番号>', '']
        seen = None
        for cid, text in rows:
            number = int(cid[1:cid.index('-')]) if cid.startswith('s') and '-' in cid else 0
            if number != seen:
                seen = number;lines.append(f'## s{number} {names.get(number, "")}'.rstrip() if number else '## 図形にない画像')
            lines.append(f'{cid}\t{text}')
    return lines


def write_new(path, data):
    path = Path(path)
    if path.exists():raise InputError('output already exists; use a fresh path')
    path.write_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design sources', description='Approved set of ARP4 documents a design may cite')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('scan', help='propose CURRENT/SUPERSEDED per version family');p.add_argument('--arp-root', required=True)
    p.add_argument('--output', required=True, help='fresh path for the proposal')
    p = sub.add_parser('show', help='Markdown table of a proposal or approved set for the approver');p.add_argument('--source-set', required=True)
    p = sub.add_parser('approve', help='approve a fresh proposal; the approver must be a person the user names')
    p.add_argument('--arp-root', required=True);p.add_argument('--proposal', required=True);p.add_argument('--approver', required=True)
    p.add_argument('--set', action='append', default=[], metavar='DOCUMENT_ID=STATUS', help='CURRENT, SUPERSEDED, REFERENCE or EXCLUDED')
    p.add_argument('--output', required=True)
    p = sub.add_parser('check', help='verify the set against ARP4 and, optionally, the sources a design cites')
    p.add_argument('--arp-root', required=True);p.add_argument('--source-set', required=True);p.add_argument('--design', help='1.1 input (JSON or YAML)')
    p = sub.add_parser('cells', help='read the documents a design may cite: every cell and drawing text with the ID a citation names')
    p.add_argument('--arp-root', required=True);p.add_argument('--source-set', required=True)
    p.add_argument('--document', help='a CURRENT or REFERENCE document ID; without it, the citable documents are listed')
    p.add_argument('--sheet', type=int, help='only this sheet number (the 1 of s1-A5)');p.add_argument('--grep', metavar='TEXT', help='only cells and drawings holding this text, in every citable document or in --document')
    p.add_argument('--offset', type=int, default=0);p.add_argument('--limit', type=int, default=3000, help='lines printed (default 3000); the rest are counted')
    p = sub.add_parser('diff', help='what changed between each superseded document and its newer version')
    p.add_argument('--arp-root', required=True);p.add_argument('--source-set', required=True)
    p.add_argument('--markdown', action='store_true', help='print a Markdown summary instead of JSON')
    args = parser.parse_args(argv)
    try:
        if args.command == 'show':
            sys.stdout.buffer.write(markdown(SourceSet.model_validate_json(Path(args.source_set).read_bytes())).encode('utf-8'));return 0
        root = Path(args.arp_root)
        if args.command == 'scan':
            proposal = scan(root);write_new(args.output, dump(proposal.model_dump()))
            counts = {}
            for e in proposal.documents:counts[e.status] = counts.get(e.status, 0) + 1
            print(json.dumps({'proposal': args.output, 'documents': counts, 'issues': proposal.issues,
                              'undecided': [e.document_id for e in proposal.documents if e.status == 'UNDECIDED']}, ensure_ascii=False));return 0
        if args.command == 'approve':
            settings = {}
            for item in args.set:
                document_id, sep, status = item.rpartition('=')
                if not sep:raise InputError(f'INVALID_SET: {item}')
                settings[document_id] = status.strip().upper()
            approved = approve(root, Path(args.proposal).read_bytes(), args.approver, settings)
            write_new(args.output, dump(approved.model_dump()))
            print(json.dumps({'source_set': args.output, 'approver': approved.approval.approver}, ensure_ascii=False));return 0
        if args.command == 'cells':
            lines = cells(root, Path(args.source_set).read_bytes(), args.document, args.sheet, args.grep)
            shown = lines[max(args.offset, 0):max(args.offset, 0) + max(args.limit, 0)]
            left = len(lines) - max(args.offset, 0) - len(shown)
            if left > 0:shown.append(f'# あと {left} 行。--offset {max(args.offset, 0) + len(shown)} で続きを出す（--sheet や --grep で絞れる）')
            sys.stdout.buffer.write(('\n'.join(shown) + '\n').encode('utf-8'));return 0
        if args.command == 'diff':
            documents, _ = read_arp(root)
            pairs, old_only = version_diff(documents, {e.document_id: e for e in load_approved(Path(args.source_set).read_bytes()).documents})
            report = {'pairs': pairs, 'old_only_values': [{'kind': k, 'value': v, 'found_in': w} for (k, v), w in sorted(old_only.items())]}
            text = render_diff(report) if args.markdown else json.dumps(report, ensure_ascii=False, indent=2) + '\n'
            sys.stdout.buffer.write(text.encode('utf-8'));return 0
        design = None
        if args.design:
            import yaml
            design = yaml.safe_load(Path(args.design).read_bytes())
            if not isinstance(design, dict):raise InputError('design input must be a mapping')
        report = check(root, Path(args.source_set).read_bytes(), design)
        print(json.dumps(report, ensure_ascii=False, indent=2));return 0 if report['status'] == 'PASS' else 2
    except ValidationError as exc:
        errors = [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': errors}, ensure_ascii=False));return 2
    except (InputError, json.JSONDecodeError, OSError) as exc:
        message = str(exc) if isinstance(exc, InputError) else type(exc).__name__
        print(json.dumps({'status': 'ERROR', 'message': message}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
