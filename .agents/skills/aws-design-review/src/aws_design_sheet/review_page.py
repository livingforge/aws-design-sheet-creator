"""Review page: the review pack as one offline HTML file, and the verdicts it exports brought back.

The page shows each row's value beside the original it was read from, filters by priority,
and takes OK/NG with a comment from the keyboard or buttons. Verdicts are kept in the
browser while the page is open and exported as a decisions file in the same form as
`aws-design review-pack record`. `imported` checks such a file against the pack (known
rows, matching fingerprints, OK/NG, a reviewer's name) before it is used. The page loads
nothing from the network and writes text only through textContent.
"""
import hashlib
import json

TEMPLATE = r"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>レビューパック</title>
<style>
:root{--bg:#fafaf8;--fg:#1d1d1b;--muted:#6b6b66;--line:#ddddd6;--card:#fff;--p1:#c0392b;--p2:#b7791f;--p3:#2f7d4a;--p4:#777;--ok:#2f7d4a;--ng:#c0392b;--focus:#2b6cb0}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b1a;--fg:#ecece8;--muted:#a3a39c;--line:#3a3a37;--card:#242423;--focus:#63b3ed}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,"Yu Gothic UI",sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:12px 16px;z-index:1}
h1{font-size:18px;margin:0 0 4px}.summary{color:var(--muted)}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}
.bar input{padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
button{padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer}
button.on{border-color:var(--focus);font-weight:600}
main{max-width:1100px;margin:0 auto;padding:12px 16px 48px}
.row{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}
.row.focus{outline:2px solid var(--focus)}
.head{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.badge{font-size:12px;padding:1px 8px;border-radius:10px;color:#fff}
.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}.P4,.DONE{background:var(--p4)}
.target{font-weight:600}.muted{color:var(--muted)}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:6px}
@media (max-width:700px){.pair{grid-template-columns:1fr}}
.pair div{border-left:3px solid var(--line);padding-left:8px;overflow-wrap:anywhere}
code{font-family:ui-monospace,Consolas,monospace}
.verdict{display:flex;gap:6px;align-items:center;margin-top:6px;flex-wrap:wrap}
.verdict input{flex:1;min-width:160px;padding:3px 6px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.OKv{border-color:var(--ok);color:var(--ok);font-weight:600}.NGv{border-color:var(--ng);color:var(--ng);font-weight:600}
</style></head><body>
<header><h1>レビューパック</h1><div class="summary" id="summary"></div>
<div class="bar"><label>レビュー担当 <input id="reviewer" placeholder="氏名"></label>
<span id="filters"></span><button id="export">判定を書き出す</button><span class="muted" id="count"></span></div>
<div class="muted">J/Kで移動、Oで OK、Nで NG。判定はこのブラウザに保存され、書き出したファイルを aws-design review-pack import で取り込む。優先度はレビューの順序であり承認ではない。</div></header>
<main id="rows"></main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
const pack=JSON.parse(document.getElementById('data').textContent);
const key='review-pack:'+pack.key;let saved={};
try{saved=JSON.parse(localStorage.getItem(key)||'{}')}catch(e){saved={}}
const verdicts=saved.verdicts||{};const reviewer=document.getElementById('reviewer');reviewer.value=saved.reviewer||'';
function store(){try{localStorage.setItem(key,JSON.stringify({verdicts:verdicts,reviewer:reviewer.value}))}catch(e){}}
reviewer.addEventListener('input',store);
const names={P1:'判断が必要',P2:'解釈の確認',P3:'抜取り確認',P4:'確認不要',DONE:'前回確認済み'};
const s=pack.summary.priorities;
document.getElementById('summary').textContent=pack.summary.rows+'行：'+Object.keys(names).map(k=>names[k]+' '+(s[k]||0)).join('・');
let shown=new Set(['P1','P2']);const filters=document.getElementById('filters');
Object.keys(names).forEach(k=>{const b=document.createElement('button');b.textContent=names[k];b.dataset.k=k;b.className=shown.has(k)?'on':'';
b.onclick=()=>{shown.has(k)?shown.delete(k):shown.add(k);b.className=shown.has(k)?'on':'';render()};filters.appendChild(b)});
const main=document.getElementById('rows');let focus=0;
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e}
function render(){main.textContent='';const visible=pack.rows.filter(r=>shown.has(r.priority));
visible.forEach((r,i)=>{const card=el('section','row'+(i===focus?' focus':''));card.dataset.i=i;
const head=el('div','head');head.appendChild(el('span','badge '+r.priority,names[r.priority]));head.appendChild(el('span','target',r.resource_id+' . '+r.property));
if(r.state)head.appendChild(el('span','muted',r.state));if(r.tier_ja)head.appendChild(el('span','muted','由来 '+r.tier_ja));
if((r.components||[]).length)head.appendChild(el('span','muted','構成要素 '+r.components.join('、')));card.appendChild(head);
const pair=el('div','pair');const v=el('div');v.appendChild(el('div','muted','設計値'));v.appendChild(el('code',null,r.value||'—'));
const o=el('div');o.appendChild(el('div','muted','原文 '+(r.evidence_at||(r.documents||[]).join('、')||'')));o.appendChild(el('div',null,r.evidence||'—'));
pair.appendChild(v);pair.appendChild(o);card.appendChild(pair);
if((r.reasons||[]).length)card.appendChild(el('div','muted','理由：'+r.reasons.join('、')));
const line=el('div','verdict');
if(r.fingerprint){const cur=verdicts[r.item_id]&&verdicts[r.item_id].fingerprint===r.fingerprint?verdicts[r.item_id]:null;
['OK','NG'].forEach(x=>{const b=el('button',cur&&cur.verdict===x?x+'v':'',x);b.onclick=()=>{set(r,x)};line.appendChild(b)});
const c=el('input');c.placeholder='コメント';c.value=cur?cur.comment:'';c.oninput=()=>{if(verdicts[r.item_id]){verdicts[r.item_id].comment=c.value;store()}};line.appendChild(c)}
else line.appendChild(el('span','muted','この行は判定を記録しない（入力や概要を直すと消える）'));
card.appendChild(line);card.onclick=()=>{focus=i;mark()};main.appendChild(card)});count()}
function set(r,x){const c=verdicts[r.item_id]&&verdicts[r.item_id].fingerprint===r.fingerprint?verdicts[r.item_id].comment:'';
verdicts[r.item_id]={fingerprint:r.fingerprint,verdict:x,comment:c};store();render()}
function mark(){main.querySelectorAll('.row').forEach((e,i)=>{e.classList.toggle('focus',i===focus);if(i===focus)e.scrollIntoView({block:'nearest'})})}
function count(){const n=pack.rows.filter(r=>r.fingerprint&&verdicts[r.item_id]&&verdicts[r.item_id].fingerprint===r.fingerprint).length;
document.getElementById('count').textContent='判定済み '+n+' / '+pack.rows.filter(r=>r.fingerprint).length}
document.addEventListener('keydown',e=>{if(e.target.tagName==='INPUT')return;const visible=pack.rows.filter(r=>shown.has(r.priority));
if(e.key==='j'){focus=Math.min(focus+1,visible.length-1);mark()}else if(e.key==='k'){focus=Math.max(focus-1,0);mark()}
else if((e.key==='o'||e.key==='n')&&visible[focus]&&visible[focus].fingerprint){set(visible[focus],e.key==='o'?'OK':'NG')}});
document.getElementById('export').onclick=()=>{if(!reviewer.value.trim()){alert('レビュー担当の氏名を入れてください');return}
const now=new Date().toISOString().replace(/\.\d+Z$/,'Z');const list=pack.rows.filter(r=>r.fingerprint&&verdicts[r.item_id]&&verdicts[r.item_id].fingerprint===r.fingerprint)
.map(r=>({item_id:r.item_id,fingerprint:r.fingerprint,verdict:verdicts[r.item_id].verdict,comment:verdicts[r.item_id].comment||'',reviewer:reviewer.value.trim(),recorded_at:now}));
const blob=new Blob([JSON.stringify({version:'1',pack:pack.key,decisions:list},null,2)],{type:'application/json'});
const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='review-decisions.json';a.click()};
render()})();
</script></body></html>
"""


def page(pack):
    """The review pack as one self-contained HTML page."""
    data = {'key': hashlib.sha256(json.dumps(pack['rows'], ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()[:16],
            'summary': pack['summary'], 'rows': pack['rows']}
    text = json.dumps(data, ensure_ascii=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return TEMPLATE.replace('__DATA__', text)


def imported(exported, pack):
    """Verdicts exported from the page, checked against the pack they were made for."""
    rows = {r['item_id']: r for r in pack['rows'] if r.get('fingerprint')}
    decisions, problems = [], []
    for d in exported.get('decisions', []):
        row = rows.get(d.get('item_id'))
        if row is None:problems.append(f"{d.get('item_id')}: パックにない行");continue
        if d.get('fingerprint') != row['fingerprint']:problems.append(f"{d['item_id']}: 値が変わった行（指紋が違う）");continue
        if d.get('verdict') not in ('OK', 'NG'):problems.append(f"{d['item_id']}: 判定が OK／NG でない");continue
        if not str(d.get('reviewer') or '').strip():problems.append(f"{d['item_id']}: レビュー担当の名前がない");continue
        decisions.append({k: d.get(k, '') for k in ('item_id', 'fingerprint', 'verdict', 'comment', 'reviewer', 'recorded_at')})
    return {'version': '1', 'decisions': decisions}, problems
