"""aws-design: one command for every tool a design project uses, as `aws-design SUBCOMMAND ...`.

Each subcommand is the module's own command line, unchanged: `aws-design flow status
--workspace WS` is what the flow module parses. Maintainer tools (rule reviews, schema
inventories, benchmarks) are not subcommands; they stay with the development checkout.
"""
import importlib
import sys

# Subcommand, module and a line for the list, in the order a project meets them.
COMMANDS = {
    'flow': ('flow', 'the next step of a workspace; run all, people, inbox, decide'),
    'sources': ('source_set', 'scan, show and approve the documents a design may cite'),
    'system': ('system_overview', 'system overview: draft, check and agree'),
    'document': ('document_cli', 'generate the design workbooks, review pack, basic design and diagram'),
    'gate': ('gates', 'machine checks of a run and of a design input'),
    'contract': ('contracts', 'list and validate handover file contracts'),
    'asks': ('asks', 'the decisions people owe the design: ledger, sheets, answers'),
    'review-pack': ('review_pack', 'record and import review verdicts'),
    'delegation': ('delegation', 'the policy that lets agents take routine decisions; audits'),
    'golden': ('golden', 'score agent outputs against settled cases'),
    'policy-pack': ('policy_packs', 'adopt a standard set of project policies'),
    'library': ('library', 'organisation library of dictionaries, policy packs and templates'),
    'changes': ('document_changes', 'propose and apply workbook edits to the input'),
    'export': ('template_export', 'fill an organisation\'s workbook template'),
    'external': ('external_sheet', 'import an external design sheet parsed by ARP4'),
    'run': ('runner', 'check documented line-format design text'),
    'check': ('cli', 'check saved checker JSON'),
    'excel': ('excel_report', 'write check results to a workbook'),
    'bootstrap': ('schema_bootstrap', 'download or check the regional CloudFormation schemas'),
}


def usage():
    width = max(map(len, COMMANDS))
    return 'usage: aws-design SUBCOMMAND [ARGS ...]\n\n' + '\n'.join(f'  {name:<{width}}  {line}' for name, (_, line) in COMMANDS.items()) + \
        '\n\nRun aws-design SUBCOMMAND --help for its arguments.\n'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help'):
        (sys.stdout if argv else sys.stderr).write(usage());return 0 if argv else 2
    name, rest = argv[0], argv[1:]
    if name not in COMMANDS:
        sys.stderr.write(f'aws-design: unknown subcommand {name!r}\n\n' + usage());return 2
    module = importlib.import_module('aws_design_sheet.' + COMMANDS[name][0])
    # A parser without its own prog names itself after argv[0].
    previous, sys.argv = sys.argv, [f'aws-design {name}', *rest]
    try:return module.main(rest) or 0
    finally:sys.argv = previous


if __name__ == '__main__':
    raise SystemExit(main())
