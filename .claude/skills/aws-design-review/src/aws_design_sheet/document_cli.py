"""Generate a document and inspect required inputs locally; not AWS design approval."""
import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .document_bindings import BindingError
from .document_model import DocumentInput, Document
from .document_normalize import InputError, normalize
from .document_workbook import workbook
from .document_policy_model import PolicyConfigurationError
from .schema_bootstrap import SchemaSetupError, resolve_schema_dir


class OverviewRefused(Exception):
    pass


class SourceSetRefused(Exception):
    def __init__(self,report):super().__init__('source set check failed');self.report=report


def source_set_report(raw,source_set,arp_root):
    """Approved ARP4 documents only: citations of superseded or excluded documents stop generation."""
    import yaml
    from .source_set import check
    design=yaml.safe_load(raw)
    if not isinstance(design,dict):raise InputError('design input must be a mapping')
    report=check(arp_root,source_set.read_bytes(),design)
    if report['status']!='PASS':raise SourceSetRefused(report)
    return report


def generate(input_path,environment,output,cfn_path=None,volume_size=10,*,evaluate_design=False,source_trace=None,external_bindings=None,
             source_set=None,arp_root=None,review_decisions=None,system_overview=None):
    resolve_schema_dir(Path(__file__).resolve().parents[2] / 'schemas')
    if output.exists():raise InputError('output directory already exists; use a fresh destination')
    raw=input_path.read_bytes();cfn_raw=cfn_path.read_bytes() if cfn_path else None
    if (source_set is None)!=(arp_root is None):raise InputError('--source-set and --arp-root are used together')
    source_check=source_set_report(raw,source_set,arp_root) if source_set else None
    overview=overview_report=None
    if system_overview is not None:
        import yaml
        from .system_overview import InputError as OverviewError,check as check_overview,load as load_overview
        try:overview=load_overview(system_overview.read_bytes())
        except (OverviewError,ValueError) as exc:raise OverviewRefused(str(exc)) from None
        overview_report=check_overview(overview,yaml.safe_load(raw))
    document=normalize(raw,environment,cfn_raw)
    if not 1<=volume_size<=50:raise InputError('volume size must be 1..50')
    if external_bindings is not None:
        if document.model_version!='1.1':raise InputError('external bindings require schema version 1.1')
        from .document_bindings import read_bindings
        document.external_bindings=read_bindings(external_bindings,document)
    if evaluate_design:
        from .document_evaluation import evaluate
        document.evaluation=evaluate(document)
        document.evaluation_status=document.evaluation.status
    report_rows=[]
    if document.model_version=='1.1':
        from .document_report import read_trace,build_report
        report_rows,trace_hash,approval=read_trace(source_trace,document)
        document.review_report=build_report(document,report_rows,trace_hash,approval)
    elif source_trace is not None:raise InputError('source trace requires schema version 1.1')
    output.mkdir(parents=True)
    volumes=[]
    if document.model_version=='1.1':
        # Volumes first and one workbook in memory at a time; the main book is then built and saved once.
        services=sorted(set(document.resource_services.values()))
        for offset in range(0,len(services),volume_size):
            selected=services[offset:offset+volume_size];name=f'services-{offset//volume_size+1:02d}.xlsx'
            part=workbook(document,services=selected,service_only=True);part.save(output/name);part.close();del part
            volumes.append({'file':name,'services':selected,'item_ids':[i.item_id for i in document.items if i.service in selected]})
        (output/'volumes.json').write_text(json.dumps(volumes,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    optional=None
    if document.model_version=='1.1':
        from .document_optional import unwritten
        optional=unwritten(document)
    book=workbook(document,services=set(),optional=optional) if document.model_version=='1.1' else workbook(document)
    if document.model_version!='1.1':book.save(output/'design.xlsx')
    if document.model_version=='1.1':
        index=book.create_sheet('分冊一覧');index.append(['ファイル','サービス','設定数'])
        for row,volume in enumerate(volumes,2):
            index.append([volume['file'],', '.join(volume['services']),len(volume['item_ids'])])
            index.cell(row,1).hyperlink=volume['file']
        index.freeze_panes='A2';index.auto_filter.ref=index.dimensions
        for column,width in [('A',25),('B',100),('C',14)]:index.column_dimensions[column].width=width
        index.print_title_rows='1:1';index.sheet_properties.pageSetUpPr.fitToPage=True
        index.page_setup.orientation='landscape';index.page_setup.paperSize=index.PAPERSIZE_A3
        index.page_setup.fitToWidth=1;index.page_setup.fitToHeight=0
        book.save(output/'design.xlsx')
    book.close();del book
    (output/'design.json').write_text(document.model_dump_json(indent=2)+'\n',encoding='utf8')
    (output/'checklist.json').write_text(document.checklist.model_dump_json(indent=2)+'\n',encoding='utf8')
    if optional is not None:
        (output/'optional-inputs.json').write_text(json.dumps(optional,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if document.design.project_policies:
        (output/'project-policy.json').write_text(document.project_policy.model_dump_json(indent=2)+'\n',encoding='utf8')
    summary={'generation_status':'GENERATED','evaluation_status':document.evaluation_status,'environment':environment,
             'resources':len(document.design.resources),'items':len(document.items),
             'differences':sum(x.comparison=='DIFFERENT' for x in document.items),
             'unresolved':sum(x.comparison=='UNRESOLVED' for x in document.items),
             'undecided':sum(x.expected.status=='UNDECIDED' for x in document.items),
             'input_completeness':document.checklist.status,'checklist':document.checklist.summary}
    summary.update(project_policy_status=document.project_policy.status,
                   project_policy_assessment=document.project_policy.assessment,
                   project_policy=document.project_policy.summary)
    if evaluate_design:
        (output/'evaluation.json').write_text(document.evaluation.model_dump_json(indent=2)+'\n',encoding='utf8')
        summary.update(aws_assessment=document.evaluation.assessment,evaluation=document.evaluation.summary,
                       evaluation_stages={k:v['status'] for k,v in document.evaluation.stages.items()})
    if document.model_version=='1.1':
        trace=document.decision_trace
        summary.update(design_decision_status=trace['status'],design_decision_assessment=trace['assessment'],
                       design_decisions=trace['summary'],basic_design_file='basic-design.md',
                       architecture_diagram_file='architecture.drawio')
        if trace['status']!='NOT_CHECKED':summary['decision_trace_file']='decision-trace.json'
    if document.model_version=='1.1':summary.update(services=len(set(document.resource_services.values())),volumes=volumes,catalog=document.catalog_provenance,
        review_report_file='review-report.json',regional_catalogs=document.regional_catalog_provenance,
        literal_matches=sum(x.comparison=='MATCH' for x in document.items),
        expression_matches=sum(x.comparison=='EXPRESSION_MATCH' for x in document.items),
        unresolved_values=sum(x.expected_resolution in ('UNRESOLVED','PARTIAL') for x in document.items),
        optional_inputs=optional['summary'],optional_inputs_file='optional-inputs.json',
        external_bindings=document.external_bindings.get('counts',{}) if document.external_bindings else {})
    from .collection_matrix import build as build_matrix,render as render_matrix
    matrix=build_matrix(document,source_check)
    (output/'collection-matrix.json').write_text(json.dumps(matrix,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (output/'collection-matrix.md').write_text(render_matrix(matrix),encoding='utf-8')
    summary.update(collection=matrix['summary'],collection_matrix_file='collection-matrix.md')
    from .review_pack import build as build_pack,render as render_pack,workbook as pack_workbook
    decisions=json.loads(review_decisions.read_text(encoding='utf-8')) if review_decisions else None
    grounding=None
    if source_check is not None:
        # The same grounding the gate runs, so the pack can tell values found in their cells from interpretations.
        import yaml
        from .grounding import Library,ground
        grounding=ground(yaml.safe_load(raw),Library.from_arp(arp_root,source_set.read_bytes()),report_rows)
    pack=build_pack(document,matrix,report_rows,source_check,decisions,overview,overview_report,grounding)
    (output/'review-pack.json').write_text(json.dumps(pack,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (output/'review-pack.md').write_text(render_pack(pack),encoding='utf-8')
    pack_book=pack_workbook(pack);pack_book.save(output/'review-pack.xlsx');pack_book.close()
    from .review_page import page as review_page
    (output/'review-pack.html').write_text(review_page(pack),encoding='utf-8')
    summary.update(review_pack=pack['summary'],review_pack_file='review-pack.md')
    if overview is not None:
        from .system_overview import render as render_overview
        (output/'system-overview.md').write_text(render_overview(overview,overview_report),encoding='utf-8')
        (output/'system-overview-check.json').write_text(json.dumps(overview_report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        summary.update(system_overview_assessment=overview_report['assessment'],system_overview=overview_report['summary']['codes'],
                       system_overview_file='system-overview.md')
    if source_check is not None:
        (output/'source-set-check.json').write_text(json.dumps(source_check,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        summary.update(source_set_status=source_check['status'],source_set_warnings=len(source_check['warnings']),
                       source_set_approver=source_check['approval']['approver'],current_not_cited=source_check['current_not_cited'])
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    if document.model_version=='1.1':
        from .document_report import render_report
        (output/'review-report.json').write_text(json.dumps(document.review_report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (output/'review-report.md').write_text(render_report(document.review_report),encoding='utf-8')
        from .document_decisions import render_basic_design
        (output/'basic-design.md').write_text(render_basic_design(document),encoding='utf-8')
        from .document_diagram import render_pages
        # Each other environment gets a page of its own, drawn from its own effective settings.
        others=[normalize(raw,e.id) for e in document.design.environments if e.id!=document.environment_id]
        (output/'architecture.drawio').write_text(render_pages(document,others),encoding='utf-8')
        if document.decision_trace['status']!='NOT_CHECKED':
            (output/'decision-trace.json').write_text(json.dumps(document.decision_trace,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        if source_trace is not None:
            saved=report_rows if approval is None else {'rows':report_rows,'document_approval':approval}
            (output/'source-trace.json').write_text(json.dumps(saved,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return summary


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path,nargs='?');p.add_argument('--environment');p.add_argument('--cfn',type=Path)
    p.add_argument('--output',type=Path);p.add_argument('--schema',choices=['input','normalized'])
    p.add_argument('--schema-version',choices=['1.0','1.1'],default='1.0');p.add_argument('--volume-size',type=int,default=10)
    p.add_argument('--evaluate',action='store_true',help='run the local checker and cfn-lint on effective design inputs')
    p.add_argument('--source-trace',type=Path,help='optional original source states and bindings; never implies source fidelity or host acceptance')
    p.add_argument('--external-bindings',type=Path,help='optional local non-secret values for EXTERNAL_REF settings; nothing is fetched from AWS')
    p.add_argument('--source-set',type=Path,help='approved aws-design sources set; sources must cite its CURRENT or REFERENCE documents')
    p.add_argument('--arp-root',type=Path,help='ARP4 project root checked against --source-set')
    p.add_argument('--review-decisions',type=Path,help='aws-design review-pack record output; unchanged OK rows leave the review pack')
    p.add_argument('--system-overview',type=Path,help='aws-design system overview checked against this input; its gaps join the review pack')
    p.add_argument('--example',action='store_true',help='print a small 1.1 input showing every shape: cited, derived and open settings, references, composite values with $design leaves, actors, connections, notes')
    p.add_argument('--types',nargs='?',const='',metavar='TEXT',help='list the resource types the catalog holds (those containing TEXT, case-insensitive); a type it lacks becomes an AWS_SERVICE actor')
    a=p.parse_args(argv)
    if a.example:
        from .input_example import EXAMPLE, NOTES
        sys.stdout.buffer.write((json.dumps(EXAMPLE,ensure_ascii=False,indent=2)+chr(10)).encode('utf-8'));sys.stdout.flush()
        sys.stderr.write(NOTES);return 0
    if a.types is not None:
        from .document_catalog import catalog
        try:known=sorted(catalog().schemas)
        except SchemaSetupError as exc:
            print(json.dumps({'generation_status':'SCHEMA_SETUP_REQUIRED','message':str(exc)}));return 2
        found=[t for t in known if a.types.casefold() in t.casefold()]
        print(json.dumps({'catalog_types':len(known),'matching':len(found),'types':found,
                          **({'note':'no type of the catalog contains this text: model the service as an actor of kind AWS_SERVICE and say so in issues'} if not found else {})},ensure_ascii=False));return 0
    if a.schema:
        if a.schema_version=='1.1':
            from .document_v11 import SchemaInput,SchemaDocument
            model=SchemaInput if a.schema=='input' else SchemaDocument
        else:model=DocumentInput if a.schema=='input' else Document
        print(json.dumps(model.model_json_schema(),ensure_ascii=False,indent=2));return 0
    if not a.input or not a.environment or not a.output:p.error('input, --environment and --output are required')
    try:
        result=generate(a.input,a.environment,a.output,a.cfn,a.volume_size,evaluate_design=a.evaluate,source_trace=a.source_trace,
                        external_bindings=a.external_bindings,source_set=a.source_set,arp_root=a.arp_root,
                        review_decisions=a.review_decisions,system_overview=a.system_overview)
    except OverviewRefused as exc:
        # Codes and IDs only.
        print(json.dumps({'generation_status':'SYSTEM_OVERVIEW_INVALID','message':str(exc)[:500]},ensure_ascii=False));return 2
    except SourceSetRefused as exc:
        # Codes, source IDs and document IDs only.
        print(json.dumps({'generation_status':'SOURCE_SET_FAILED','errors':exc.report['errors']},ensure_ascii=False));return 2
    except SchemaSetupError as exc:
        print(json.dumps({'generation_status':'SCHEMA_SETUP_REQUIRED','message':str(exc)}));return 2
    except BindingError as exc:
        # Codes and reference names only; bound values are never echoed.
        print(json.dumps({'generation_status':'BINDING_ERROR','error_code':str(exc)},ensure_ascii=False));return 2
    except PolicyConfigurationError as exc:
        print(json.dumps({'generation_status':'POLICY_CONFIGURATION_ERROR','error_code':exc.code}));return 2
    except ValidationError as exc:
        policy_error=any(e['loc'] and e['loc'][0] in ('project_policies','policy_exceptions') for e in exc.errors(include_input=False,include_context=False))
        errors=exc.errors(include_input=False,include_context=False)
        # The input's own rules (value_error) name the IDs at fault and never a value; other errors give a location only.
        from .contracts import MESSAGE_LENGTH,shape_errors
        messages=[{'loc':[str(x) for x in e['loc']],'message':e['msg'].removeprefix('Value error, ')[:MESSAGE_LENGTH]} for e in errors if e['type']=='value_error'][:20]
        # Faults of the file's shape, one row per kind: where, what the contract expects there, and how many places.
        shapes=shape_errors(exc)
        print(json.dumps({'generation_status':'POLICY_CONFIGURATION_ERROR' if policy_error else 'STRUCTURE_ERROR','error_count':exc.error_count(),
                          'error_types':sorted({e['type'] for e in errors}),**({'messages':messages} if messages else {}),
                          **({'shape_errors':shapes} if shapes else {})},ensure_ascii=False));return 2
    except (InputError,OSError,ValueError,RecursionError):
        # No exception repr, raw source, parser excerpt or secret payload is logged.
        print(json.dumps({'generation_status':'STRUCTURE_ERROR','message':'Input or output validation failed; no source values logged.'}));return 2
    print(json.dumps(result));return 3 if result['evaluation_status'] in ('FAILED','SKIPPED') or result['project_policy_status']=='FAILED' else 0


if __name__=='__main__':raise SystemExit(main())
