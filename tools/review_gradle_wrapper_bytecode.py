"""Reproduce exact wrapper static/VM verification without initializing target code.

Uses only an explicitly selected existing JDK. No download, installation, wrapper
execution or automatic scanner clearance. The recorded semantic review is a
separate human review of the complete disassembly and security-sensitive flows.
"""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
import zipfile

KNOWN = {
    '498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17': ('8.9', 43504),
    '2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046': ('8.10', 43583),
}


def review(jar, java_home, output):
    raw=jar.read_bytes();checksum=hashlib.sha256(raw).hexdigest()
    if checksum not in KNOWN or len(raw)!=KNOWN[checksum][1]:
        raise ValueError('Not an independently reviewed wrapper archive')
    output.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(jar) as archive:
        names=sorted(item.filename[:-6].replace('/','.') for item in archive.infolist() if item.filename.endswith('.class'))
    if len(names)!=31 or any(not re.fullmatch(r'org\.gradle\.[A-Za-z0-9_.$]+',name) for name in names):
        raise ValueError('Unexpected wrapper class inventory')
    source=Path(__file__).with_name('VerifyWrapperTypes.java')
    with tempfile.TemporaryDirectory(prefix='stellar-wrapper-types-') as directory:
        subprocess.run([str(java_home/'bin/javac'),'-d',directory,str(source)],check=True,timeout=30,capture_output=True)
        verified=subprocess.run([str(java_home/'bin/java'),'-Xverify:all','-cp',directory,'VerifyWrapperTypes',str(jar.resolve())],check=True,timeout=30,capture_output=True).stdout
    expected=[('STRUCTURALLY_VERIFIED_WITHOUT_INITIALIZATION '+name).encode() for name in names]
    if verified.splitlines()[:-1]!=expected or verified.splitlines()[-1]!=b'classes=31 methods_and_constructors=105 initialized=false invoked=false':
        raise ValueError('Incomplete VM verification')
    disassembly=subprocess.run([str(java_home/'bin/javap'),'-classpath',str(jar.resolve()),'-c','-p','-s','-constants',*names],check=True,timeout=30,capture_output=True).stdout
    if b'invokedynamic' in disassembly or re.search(rb'^.*\bnative\s+.*;',disassembly,re.M):
        raise ValueError('Unexpected dynamic/native method capability')
    (output/'bytecode.txt').write_bytes(disassembly)
    (output/'verification.txt').write_bytes(verified)
    document={'version':KNOWN[checksum][0],'archive_sha256':checksum,'archive_bytes':len(raw),'classes':31,
              'methods_and_constructors':105,'initialized':False,'invoked':False,
              'disassembly_sha256':hashlib.sha256(disassembly).hexdigest(),
              'verification_sha256':hashlib.sha256(verified).hexdigest(),
              'semantic_review_automatically_granted':False,'distribution_clearance':False}
    (output/'structural-review.json').write_text(json.dumps(document,indent=2)+'\n')
    return document


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar',type=Path,required=True)
    parser.add_argument('--java-home',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    arguments=parser.parse_args()
    print(json.dumps(review(arguments.jar,arguments.java_home,arguments.output),sort_keys=True))
