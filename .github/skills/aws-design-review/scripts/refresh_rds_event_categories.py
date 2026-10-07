"""Refresh the documentation snapshot; review its diff before using it.

This is an advisory positive list, not a closed list of AWS capabilities.
"""
import hashlib
from html.parser import HTMLParser
import json
import re
from pathlib import Path
from urllib.request import urlopen
from datetime import date

HEADINGS = {
    'DB cluster events': 'db-cluster', 'DB cluster snapshot events': 'db-cluster-snapshot',
    'DB instance events': 'db-instance', 'DB parameter group events': 'db-parameter-group',
    'DB security group events': 'db-security-group', 'DB snapshot events': 'db-snapshot',
    'RDS Proxy events': 'db-proxy', 'Blue/green deployment events': 'blue-green-deployment',
    'Custom engine version events': 'custom-engine-version',
}


class Categories(HTMLParser):
    def __init__(self):
        super().__init__()
        self.heading = None
        self.cell = None
        self.column = 0
        self.row = []
        self.kind = None
        self.values = {}

    def handle_starttag(self, tag, attrs):
        if tag == 'h2':
            self.heading = []
        elif tag == 'tr':
            self.column = 0
            self.row = []
        elif tag == 'td':
            self.column += 1
            self.cell = []

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == 'h2' and self.heading is not None:
            self.kind = HEADINGS.get(' '.join(''.join(self.heading).split()))
            self.heading = None
        if tag == 'td' and self.cell is not None:
            self.row.append(''.join(self.cell))
            self.cell = None
        if tag == 'tr':
            if self.kind and len(self.row) >= 2 and re.fullmatch(r'\s*RDS-EVENT-\d+\s*', self.row[1]):
                for category in self.row[0].split(','):
                    category = ' '.join(category.split())
                    if category and category != 'None':
                        self.values.setdefault(self.kind, set()).add(category)


def main():
    sources, values = [], {}
    for guide in ('UserGuide', 'AuroraUserGuide'):
        url = f'https://docs.aws.amazon.com/AmazonRDS/latest/{guide}/USER_Events.Messages.html'
        with urlopen(url, timeout=30) as response:
            raw = response.read()
        parser = Categories()
        parser.feed(raw.decode('utf-8'))
        if not parser.values.get('db-instance') or not parser.values.get('db-cluster'):
            raise ValueError('documentation structure changed')
        sources.append({'url': url, 'sha256': hashlib.sha256(raw).hexdigest()})
        for kind, categories in parser.values.items():
            values.setdefault(kind, set()).update(categories)
    payload = {'version': '1.0.0', 'checked_at': date.today().isoformat(),
               'sources': sources, 'categories': {k: sorted(v) for k, v in sorted(values.items())}}
    path = Path(__file__).resolve().parents[1] / 'rules/rds-event-categories.json'
    path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print({k: len(v) for k, v in payload['categories'].items()})


if __name__ == '__main__':
    main()
