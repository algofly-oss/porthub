#!/usr/bin/env python3
"""Merge reviewed optional helper platform outputs; validates and never uploads."""
import argparse,importlib.util,json,shutil,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('media_release',Path(__file__).with_name('media-release.py'));media=importlib.util.module_from_spec(spec);spec.loader.exec_module(media)
def merge(inputs,destination,version,source_revision=None,validate_executable=None):
 media.numeric(version)
 if not inputs or destination.exists() or destination.is_symlink():raise ValueError('Use reviewed helper inputs and a new merge directory')
 records=[];sources={}
 for directory in inputs:
  if directory.is_symlink() or not directory.is_dir():raise ValueError('Unsafe media platform input')
  path=directory/media.ASSET
  if path.is_symlink() or not path.is_file() or path.stat().st_size>media.MAX_MANIFEST:raise ValueError('Missing bounded media platform manifest')
  raw=json.loads(path.read_bytes());media.exact_fields(raw,'schema_version namespace repository release artifacts')
  if type(raw['schema_version']) is not int or raw['schema_version']!=1 or raw['namespace']!='porthub-media' or raw['repository']!='algofly-oss/porthub' or media.numeric(raw['release'])>media.numeric(version) or not isinstance(raw['artifacts'],list) or not 1<=len(raw['artifacts'])<=3:raise ValueError('Untrusted media platform manifest')
  for artifact in raw['artifacts']:
   target=artifact.get('target')
   if target not in media.TARGETS or target in sources:raise ValueError('Duplicate or unknown helper target')
   if source_revision is not None and artifact.get('source_revision')!=source_revision:raise ValueError('Helper source differs from reviewed source')
   records.append(artifact);sources[target]=directory/('porthub-media-helper-'+target+'.tar.gz')
 candidate={'schema_version':1,'namespace':'porthub-media','repository':'algofly-oss/porthub','release':version,'artifacts':sorted(records,key=lambda a:a['target'])};media.parse(json.dumps(candidate),version)
 destination.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='.porthub-media-merge-',dir=destination.parent) as temp:
  output=Path(temp)/'assets';output.mkdir(mode=0o700)
  for artifact in candidate['artifacts']:
   source=sources[artifact['target']];media.verified(source,artifact['archive']);shutil.copyfile(source,output/source.name);(output/source.name).chmod(0o600)
  (output/media.ASSET).write_text(json.dumps(candidate,indent=2)+'\n');(output/media.ASSET).chmod(0o600)
  media.verify(output,version,validate_executable);output.rename(destination)
 return destination

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,action='append',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--version',required=True);p.add_argument('--source-revision');a=p.parse_args();merge(a.input,a.output,a.version,a.source_revision);print('Verified optional media assets: '+str(a.output))
if __name__=='__main__':main()
