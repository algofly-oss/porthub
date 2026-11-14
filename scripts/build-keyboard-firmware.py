#!/usr/bin/env python3
"""Build both Bluetooth HID firmware targets and stage verified browser assets."""
import hashlib,json,os,pathlib,shutil,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
version=os.environ.get('PORTHUB_VERSION') or subprocess.check_output(['sh',str(root/'scripts/release-version.sh')],text=True).strip()
subprocess.run([str(root/'firmware/keyboard/build.sh'),version],check=True)
destination=root/'ui/public/keyboard-firmware';destination.mkdir(parents=True,exist_ok=True)
images=[]
for chip in ['esp32','esp32c3']:
    source=root/'firmware/keyboard/dist'/f'porthub-keyboard-{chip}.bin'
    digest=hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(source,destination/source.name)
    images.append(dict(chip=chip,filename=source.name,version=version,size=source.stat().st_size,sha256=digest))
(destination/'manifest.json').write_text(json.dumps(dict(version=version,images=images),indent=2)+'\n')
print('Staged verified ESP32 and ESP32-C3 browser firmware')
