#!/usr/bin/env python3
"""Fetch trusted gateway history and preserve immutable component identities."""
import argparse
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlsplit

MAX_CATALOG = 512 * 1024
TOOLS = {'stats', 'terminal', 'sync', 'tor', 'transfer'}
SAME_TOOL = ('component', 'version', 'target', 'core', 'protocols', 'source_revision', 'build_inputs', 'executable')

def numeric(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('Invalid stable component history version')
    return tuple(map(int, value.split('.')))

def catalog(value):
    if value.get('schema_version') == 2:
        value = value.get('components', {})
    if value.get('schema_version') != 1 or value.get('repository') != 'algofly-oss/porthub':
        raise ValueError('Invalid trusted component catalog identity')
    numeric(value.get('release'))
    artifacts = value.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 4096:
        raise ValueError('Invalid trusted component catalog inventory')
    seen = set()
    for row in artifacts:
        if not isinstance(row, dict) or any(key not in row for key in SAME_TOOL):
            raise ValueError('Incomplete component history identity')
        numeric(row['version'])
        if row['component'] not in TOOLS or not isinstance(row['target'], str):
            raise ValueError('Invalid component history tool or target')
        identity = tuple(row[key] for key in ('component', 'version', 'target'))
        if identity in seen:
            raise ValueError('Duplicate component history identity')
        seen.add(identity)
    return value

def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CATALOG:
        raise ValueError('Unsafe or oversized component history file')
    return catalog(json.loads(path.read_bytes()))

def read_trusted(path):
    receipt_path=path.with_name(path.name+'.provenance.json')
    if receipt_path.is_symlink() or not receipt_path.is_file() or receipt_path.stat().st_size>4096:
        raise ValueError('Missing trusted catalog acquisition receipt')
    receipt=json.loads(receipt_path.read_bytes())
    parsed=urlsplit(receipt.get('gateway',''))
    if (receipt.get('schema_version')!=1 or parsed.scheme!='https' or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None,443)):
        raise ValueError('Invalid trusted catalog acquisition identity')
    value=read(path)
    if receipt.get('sha256')!=hashlib.sha256(path.read_bytes()).hexdigest() or receipt.get('release')!=value['release']:
        raise ValueError('Trusted catalog acquisition checksum mismatch')
    return value

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Component history redirects are forbidden')

def fetch(base):
    parsed = urlsplit(base or '')
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError('Component history requires a trusted HTTPS gateway')
    with build_opener(NoRedirect()).open(Request(base.rstrip('/')+'/api/downloads/components/catalog', headers={'User-Agent':'PortHub component history'}), timeout=15) as response:
        if response.status != 200:
            raise ValueError('Trusted gateway component history unavailable')
        payload = response.read(MAX_CATALOG+1)
    if len(payload) > MAX_CATALOG:
        raise ValueError('Component history exceeds size limit')
    return catalog(json.loads(payload))

def floor(history, tool):
    return max((numeric(row['version']) for row in history['artifacts'] if row['component'] == tool), default=None)

def reuse_safe(history, receipt):
    target=receipt['target'].replace('-musleabihf','-gnueabihf').replace('-musl','-gnu')
    selected=[row for row in history['artifacts'] if (row['component'],row['version'],row['target'])==(receipt['tool'],receipt['version'],target)]
    if not selected:
        return True
    old=selected[0];recipe=receipt['build']['recipe']
    return (old['core']==recipe['core'] and old['protocols']==recipe['protocols']
            and old['source_revision']==receipt['source_revision'] and old['build_inputs']==receipt['fingerprint']
            and old['executable']=={key:receipt['binary'][key] for key in ('size','sha256')})

def validate_successor(candidate, previous):
    candidate, previous = catalog(candidate), catalog(previous)
    if numeric(candidate['release']) < numeric(previous['release']):
        raise ValueError('Component catalog downgrade rejected')
    if candidate['release'] == previous['release'] and candidate != previous:
        raise ValueError('Published component catalog changed')
    old = {tuple(row[key] for key in ('component','version','target')):row for row in previous['artifacts']}
    for row in candidate['artifacts']:
        prior = old.get(tuple(row[key] for key in ('component','version','target')))
        if prior and any(row[key] != prior[key] for key in SAME_TOOL):
            raise ValueError('Published component version changed: '+row['component']+' '+row['version']+' '+row['target'])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    value=fetch(args.gateway)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as output:
        json.dump(value,output,sort_keys=True);output.write('\n')
    receipt={'schema_version':1,'gateway':args.gateway,'release':value['release'],
             'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
             'fetched_at':datetime.now(timezone.utc).isoformat()}
    with args.output.with_name(args.output.name+'.provenance.json').open('x') as output:
        json.dump(receipt,output,sort_keys=True);output.write('\n')
if __name__ == '__main__':main()
