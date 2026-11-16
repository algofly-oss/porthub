#!/usr/bin/env python3
"""Strict OPTIONAL media namespace. Never changes the legacy component manifest."""
import hashlib,importlib.util,json,re,tarfile,tempfile
from pathlib import Path
ASSET='porthub-media-components.json'
TARGETS={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-pc-windows-msvc'}
GNU={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu'}
ARCHIVES={'porthub-media-helper-'+target+'.tar.gz' for target in TARGETS}
MAX_MANIFEST=512*1024;MAX_EXECUTABLE=128*1024*1024;MAX_ARCHIVE=512*1024*1024
def numeric(value):
 if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):raise ValueError('Invalid media version')
 return tuple(map(int,value.split('.')))
def blob(value,maximum):
 if not isinstance(value,dict) or set(value)!={'size','sha256'} or type(value['size']) is not int or not 0<value['size']<=maximum or not isinstance(value['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',value['sha256']):raise ValueError('Invalid media blob')
def exact_fields(value,fields):
 if not isinstance(value,dict) or set(value)!=set(fields.split()):raise ValueError('Unexpected media manifest fields')
def parse(data,version):
 if len(data)>MAX_MANIFEST:raise ValueError('Media manifest exceeds bound')
 def unique(rows):
  value={}
  for k,v in rows:
   if k in value:raise ValueError('Duplicate media JSON field')
   value[k]=v
  return value
 m=json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError('Nonfinite media JSON')))
 exact_fields(m,'schema_version namespace repository release artifacts')
 if type(m['schema_version']) is not int or m['schema_version']!=1 or m['namespace']!='porthub-media' or m['repository']!='algofly-oss/porthub' or m['release']!=version:raise ValueError('Untrusted media release namespace')
 numeric(m['release']);targets=set()
 if not isinstance(m['artifacts'],list) or not 2<=len(m['artifacts'])<=3:raise ValueError('Incomplete media artifact set')
 for a in m['artifacts']:
  exact_fields(a,'version target core protocol source_revision build_inputs executable archive');numeric(a['version'])
  if a['target'] not in TARGETS or a['target'] in targets or type(a['protocol']) is not int or a['protocol']!=1:raise ValueError('Invalid/duplicate media target or protocol')
  targets.add(a['target'])
  if not isinstance(a['core'],str) or not a['core'].startswith('>=') or numeric(a['core'][2:])<(1,11,34):raise ValueError('Media requires agent >=1.11.34')
  if not isinstance(a['source_revision'],str) or not re.fullmatch('[a-f0-9]{40}',a['source_revision']) or not isinstance(a['build_inputs'],str) or not re.fullmatch('[a-f0-9]{64}',a['build_inputs']):raise ValueError('Invalid media provenance')
  blob(a['executable'],MAX_EXECUTABLE);blob(a['archive'],MAX_ARCHIVE)
 if not GNU<=targets:raise ValueError('Both GNU media helpers are required')
 if len({(a['version'],a['source_revision'],a['build_inputs']) for a in m['artifacts']})!=1:raise ValueError('Media targets must share reviewed source and build inputs')
 return m
def optional_names(names):
 names=set(names);media={n for n in names if n==ASSET or n.startswith('porthub-media-helper-')}
 if not media:return set()
 if media not in [{ASSET}|{'porthub-media-helper-'+t+'.tar.gz' for t in GNU},{ASSET}|ARCHIVES]:raise ValueError('Incomplete or unknown optional media asset set')
 return media
def verified(path,record):
 if path.is_symlink() or not path.is_file() or path.stat().st_size!=record['size']:raise ValueError('Media artifact size/type mismatch')
 with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
 if digest!=record['sha256']:raise ValueError('Media artifact digest mismatch')
def verify(directory,version,validate_executable=None):
 names=optional_names(p.name for p in directory.iterdir())
 if not names:return set()
 manifest=directory/ASSET
 if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size>MAX_MANIFEST:raise ValueError('Invalid media manifest file')
 m=parse(manifest.read_bytes(),version);expected={ASSET}
 if validate_executable is None:
  spec=importlib.util.spec_from_file_location('media_packager',Path(__file__).with_name('package-media-helper.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  validate_executable=getattr(module,'validate_executable',module.validate_elf)
 for a in m['artifacts']:
  name='porthub-media-helper-'+a['target']+'.tar.gz';expected.add(name);archive=directory/name;verified(archive,a['archive'])
  member='media-helper/'+a['version']+'/porthub-media-helper'+('.exe' if 'windows' in a['target'] else '')
  with tempfile.TemporaryDirectory(prefix='porthub-media-verify-') as tmp:
   output=Path(tmp)/('helper.exe' if 'windows' in a['target'] else 'helper')
   with tarfile.open(archive,'r:gz') as tar:
    count=0
    for entry in tar:
     count+=1
     if count!=1 or entry.name!=member or not entry.isreg() or entry.size!=a['executable']['size'] or entry.mode!=0o755:raise ValueError('Invalid media archive member')
     stream=tar.extractfile(entry)
     with output.open('xb') as dest:
      remaining=a['executable']['size']
      while remaining:
       chunk=stream.read(min(65536,remaining))
       if not chunk:raise ValueError('Truncated media executable')
       dest.write(chunk);remaining-=len(chunk)
     verified(output,a['executable']);validate_executable(output,a['target'])
    if count!=1:raise ValueError('Missing media archive member')
 if names!=expected:raise ValueError('Media manifest does not match optional assets')
 return names

def validate_successor(candidate,previous):
 if candidate is None or previous is None:return
 candidate=parse(json.dumps(candidate),candidate['release']);previous=parse(json.dumps(previous),previous['release'])
 if numeric(candidate['release'])<numeric(previous['release']):raise ValueError('Media catalog downgrade rejected')
 if candidate['release']==previous['release'] and candidate!=previous:raise ValueError('Published media catalog changed')
 old={(a['version'],a['target']):a for a in previous['artifacts']}
 for a in candidate['artifacts']:
  prior=old.get((a['version'],a['target']))
  if prior is not None and a!=prior:raise ValueError('Published media helper identity changed')
  versions=[numeric(p['version']) for p in previous['artifacts'] if p['target']==a['target']]
  if versions and numeric(a['version'])<max(versions):raise ValueError('Media helper version downgrade rejected')
def fetch_catalog(base):
 from urllib.request import Request,build_opener,HTTPRedirectHandler
 from urllib.error import HTTPError
 from urllib.parse import urlsplit
 parsed=urlsplit(base)
 if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None,443):raise ValueError('Invalid trusted media gateway')
 class NoRedirect(HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise ValueError('Media history redirect rejected')
 try:
  with build_opener(NoRedirect()).open(Request(base.rstrip('/')+'/api/downloads/media/catalog',headers={'User-Agent':'PortHub-media-publication'}),timeout=20) as response:data=response.read(MAX_MANIFEST+1)
 except HTTPError as error:
  if error.code==404:return None
  raise ValueError('Trusted media history unavailable') from None
 if len(data)>MAX_MANIFEST:raise ValueError('Trusted media history exceeds bound')
 raw=json.loads(data);return parse(data,raw.get('release'))
