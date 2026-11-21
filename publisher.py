"""Public-repository publisher. Reads private release refs with a read-only key.
Only immutable, verified distribution archives and signed metadata are published.
"""
import base64, hashlib, io, json, os, re, subprocess, tempfile, zipfile, tarfile, datetime
from pathlib import Path

SOURCE = 'trlstdin/rororororo'
MINIMUM = (6, 0, 10)  # Earlier historical candidates were not accepted for this channel.
TARGETS = {'win10-x64', 'win11-x64', 'linux-x64-cloud'}
PUBLIC = os.environ['PUBLIC_REPOSITORY']

def run(*args, cwd=None, data=None):
    p = subprocess.run(args, cwd=cwd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        # Do not print invocation environments, SSH credentials or private source.
        details=p.stderr.decode('utf-8','replace')
        category=next((label for label in ['error in libcrypto','invalid format','Permission denied','Host key verification failed','Repository not found','Could not resolve','Connection refused','Connection timed out'] if label in details),'command error')
        raise RuntimeError(f'{args[0]} failed with exit {p.returncode}: {category}')
    return p.stdout

def api(route, body=None):
    args = ['gh', 'api', route]
    if body is not None:
        args += ['--method', 'PUT' if '/contents/' in route else 'POST', '--input', '-']
    return json.loads(run(*args, data=None if body is None else json.dumps(body).encode()) or b'null')

def version(v):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', v):
        raise ValueError('Invalid release version')
    return tuple(map(int, v.split('.')))

def sha256(file):
    h=hashlib.sha256()
    with open(file,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def block_index(file):
    # Same content-defined boundaries as the client's existing block cache.
    # This is production release metadata generation, not application execution.
    program=r"""const fs=require('fs'),crypto=require('crypto');
const gear=new Uint32Array(256);let seed=0x51a7c3d9;for(let i=0;i<256;i++){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;gear[i]=seed>>>0;}
(async()=>{let offset=0n,length=0,hash=0,parts=[];const blocks=[],whole=crypto.createHash('sha256');function finish(){if(!length)return;const bytes=Buffer.concat(parts,length);blocks.push({offset:String(offset),size:String(length),sha256:crypto.createHash('sha256').update(bytes).digest('hex')});offset+=BigInt(length);length=0;hash=0;parts=[];}
for await(const input of fs.createReadStream(process.argv[1])){whole.update(input);let start=0;for(let i=0;i<input.length;i++){hash=((hash<<1)+gear[input[i]])>>>0;length++;if(length>=65536&&((hash&0xfffff)===0||length>=4194304)){parts.push(input.subarray(start,i+1));finish();start=i+1;}}if(start<input.length)parts.push(input.subarray(start));}finish();console.log(JSON.stringify({schema:1,size:String(offset),sha256:whole.digest('hex'),blocks}));})().catch(()=>process.exit(1));"""
    return json.loads(run('node','-e',program,str(file)))

def verify_package(file, v, target, source, release_sha):
    if target == 'linux-x64-cloud':
        archive=tarfile.open(file)
        members=[m for m in archive if not m.isdir()]
        entries={m.name:m for m in members}
        if len(entries)!=len(members):raise ValueError('Duplicate archive entries')
        if any(not m.isfile() for m in entries.values()): raise ValueError('Archive links or special files refused')
        read=lambda n: archive.extractfile(entries[n]).read()
        prefix='release/app/'
        metadata='BUILD.json'
    else:
        archive=zipfile.ZipFile(file)
        entries={i.filename:i for i in archive.infolist() if not i.is_dir()}
        if len(entries)!=len([i for i in archive.infolist() if not i.is_dir()]): raise ValueError('Duplicate archive entries')
        if any((i.external_attr>>16)&0o170000 == 0o120000 for i in entries.values()): raise ValueError('Archive links refused')
        read=archive.read
        prefix='resources/app/'
        metadata='PACKAGE.json'
    for n in entries:
        if n.startswith(('/', '\\')) or '\\' in n or ':' in n or '..' in n.split('/'):
            raise ValueError('Unsafe package path')
        if any(p.lower() in {'.ssh','.git','profile','recovery','browser-profile'} for p in n.split('/')):
            raise ValueError('Private runtime directory in distribution')
        if Path(n).name in {'identity.json','client-launch.json','peer.json','hosts.yml'}:
            raise ValueError('Private state in distribution')
    if json.loads(read('build-info.json')) != {'version':v,'target':target}: raise ValueError('Package platform/version mismatch')
    meta=json.loads(read(metadata)); commit=meta['sourceCommit']
    if not re.fullmatch('[a-f0-9]{40}',commit): raise ValueError('Invalid source commit')
    if meta.get('credentialsIncluded') is True or meta.get('privateStateIncluded') is True:raise ValueError('Private state declared in distribution')
    if meta.get('version')!=v or meta.get('target')!=target: raise ValueError('Package metadata mismatch')
    if json.loads(read(prefix+'package.json'))['version']!=v: raise ValueError('Application version mismatch')
    run('git','fetch','--filter=blob:none','origin',commit,cwd=source)
    run('git','diff','--exit-code',commit,release_sha,'--','src','desktop','launchers','cloud','package-lock.json',cwd=source)
    # git archive applies export/EOL attributes; compare canonical committed blobs.
    records=run('git','ls-tree','-r','-z',commit,'--','src','desktop','launchers','cloud',cwd=source).split(b'\0')
    entries_to_read=[]
    for record in records:
        if not record:continue
        header,name=record.split(b'\t',1);mode,kind,oid=header.split()
        if kind!=b'blob' or mode not in (b'100644',b'100755'):raise ValueError('Unsupported source tree entry')
        entries_to_read.append((name.decode('utf-8'),oid))
    stream=io.BytesIO(run('git','cat-file','--batch',cwd=source,data=b''.join(oid+b'\n' for _,oid in entries_to_read)))
    expected={}
    for name,oid in entries_to_read:
        actual_oid,kind,size=stream.readline().rstrip(b'\n').split()
        if actual_oid!=oid or kind!=b'blob':raise ValueError('Frozen source blob mismatch')
        content=stream.read(int(size))
        if len(content)!=int(size) or stream.read(1)!=b'\n':raise ValueError('Incomplete frozen source blob')
        expected[name]=content
    if target=='linux-x64-cloud':
        expected['src/pro/desktop-lifecycle.cjs']=expected['src/pro/client-lifecycle.cjs']
        expected['src/pro/client-lifecycle.cjs']=expected['cloud/client-lifecycle.cjs']
    expected={n:b for n,b in expected.items() if n.split('/')[0] in {'src','desktop','launchers'}}
    actual={n[len(prefix):]:read(n) for n in entries if n.startswith(prefix) and n[len(prefix):].split('/')[0] in {'src','desktop','launchers'}}
    if expected!=actual: raise ValueError('Packaged application differs from frozen source')
    for n in ('package.json','package-lock.json'):
        expected_json=json.loads(run('git','show',commit+':'+n,cwd=source))
        expected_json['version']=v
        if n=='package-lock.json':expected_json['packages']['']['version']=v
        if json.loads(read(prefix+n))!=expected_json:raise ValueError('Package dependency declarations differ from source')
    if read(prefix+'update-source.json')!=run('git','show',commit+':update-source.json',cwd=source):raise ValueError('Packaged update trust configuration differs from source')
    archive.close()
    return commit

def main():
    with tempfile.TemporaryDirectory() as tmp:
        work=Path(tmp); key=work/'source-key'; key.write_text(os.environ.pop('SOURCE_DEPLOY_KEY').replace('\r\n','\n').strip()+'\n'); key.chmod(0o600)
        signing=work/'signing.pem'; signing.write_text(os.environ.pop('CHANNEL_SIGNING_KEY').replace('\r\n','\n').strip()+'\n'); signing.chmod(0o600)
        # Ubuntu hosted runners contain GitHub host keys. Fetch official published keys
        # over verified HTTPS instead of blindly trusting ssh-keyscan output.
        meta=api('meta'); known=work/'known_hosts'
        known.write_text(''.join('github.com '+k+'\n' for k in meta['ssh_keys']))
        os.environ['GIT_SSH_COMMAND']=f'ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known}'
        os.environ['GIT_LFS_SKIP_SMUDGE']='1'
        source=work/'source'; run('git','init',str(source));run('git','remote','add','origin','git@github.com:'+SOURCE+'.git',cwd=source)
        refs=run('git','ls-remote','origin','refs/heads/release/*',cwd=source).decode().splitlines()
        selected=[]
        for line in refs:
            commit,ref=line.split();v=ref.removeprefix('refs/heads/release/')
            if re.fullmatch(r'\d+\.\d+\.\d+',v) and version(v)>=MINIMUM: selected.append((version(v),v,commit))
        releases=[];page=1
        while True:
            batch=api(f'repos/{PUBLIC}/releases?per_page=100&page={page}');releases+=batch
            if len(batch)<100:break
            page+=1
        existing={r['tag_name']:r for r in releases};items=[]
        for _,v,commit in sorted(selected):
            tag='v'+v;old=existing.get(tag)
            if old and not old['draft']:
                metadata=next((a for a in old['assets'] if a['name']=='verified-release.json'),None)
                if not metadata:raise ValueError('Published release has no verification receipt')
                import urllib.request
                receipt=json.load(urllib.request.urlopen(metadata['browser_download_url']))
                if receipt['sourceRefSha']!=commit:raise ValueError('Published private release branch was rewritten')
                items+=receipt['releases'];continue
            run('git','fetch','--filter=blob:none','origin',commit,cwd=source)
            manifest=json.loads(run('git','show',commit+':release.json',cwd=source))
            if set(manifest)!={'schema','targets'} or manifest['schema']!=1 or not manifest['targets'] or len(set(manifest['targets']))!=len(manifest['targets']) or not set(manifest['targets'])<=TARGETS:raise ValueError('Invalid release manifest')
            artifacts=[];current=[]
            for target in manifest['targets']:
                name='SSHRelayPro-'+v+'-'+target+('.tar.gz' if target=='linux-x64-cloud' else '.zip');namepath='packages/'+name
                pointer=run('git','show',commit+':'+namepath,cwd=source).decode()
                match=re.fullmatch(r'version https://git-lfs.github.com/spec/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize ([1-9][0-9]*)\r?\n?',pointer)
                if not match:raise ValueError('Invalid package LFS pointer')
                digest,size=match.groups()
                run('git','lfs','fetch','--include='+namepath,'--exclude=','origin',commit,cwd=source)
                objectfile=source/'.git/lfs/objects'/digest[:2]/digest[2:4]/digest
                if objectfile.stat().st_size!=int(size) or sha256(objectfile)!=digest:raise ValueError('Package digest mismatch')
                if int(size)>=2*1024**3:raise ValueError('Package exceeds GitHub release asset size limit')
                source_commit=verify_package(objectfile,v,target,source,commit)
                package=work/name;os.link(objectfile,package);artifacts.append(package)
                index=block_index(package)
                if index['sha256']!=digest or index['size']!=size:raise ValueError('Block index identity differs')
                current.append(dict(version=v,target=target,sha=commit,sha256=digest,size=size,url=f'https://github.com/{PUBLIC}/releases/download/{tag}/{name}',blocks=index))
            receipt=work/'verified-release.json';receipt.write_text(json.dumps({'schema':1,'sourceRefSha':commit,'releases':current},sort_keys=True));artifacts.append(receipt)
            if not old:run('gh','release','create',tag,'--repo',PUBLIC,'--draft','--title',v,'--notes','Verified distribution archives. Private source repository is not published.')
            # Draft assets are retryable. Published releases are never overwritten.
            run('gh','release','upload',tag,*map(str,artifacts),'--repo',PUBLIC,'--clobber')
            assets=api(f'repos/{PUBLIC}/releases/tags/{tag}')['assets']
            for file in artifacts:
                asset=next(a for a in assets if a['name']==file.name)
                if asset['size']!=file.stat().st_size or asset.get('digest')!='sha256:'+sha256(file):raise ValueError('Uploaded asset verification failed')
            run('gh','release','edit',tag,'--repo',PUBLIC,'--draft=false','--latest=false')
            items+=current
        payload=json.dumps({'schema':1,'releases':items,'generatedDay':datetime.datetime.now(datetime.timezone.utc).date().isoformat()},sort_keys=True,separators=(',',':')).encode();data=work/'payload';data.write_bytes(payload)
        signature=run('openssl','pkeyutl','-sign','-inkey',str(signing),'-rawin','-in',str(data))
        envelope=json.dumps({'schema':1,'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signature).decode()},sort_keys=True).encode()
        # Do not drop previously published entries if a private branch is removed.
        present=None
        try:present=api(f'repos/{PUBLIC}/contents/channel.json')
        except RuntimeError:pass
        if present:
            previous=json.loads(base64.b64decode(present['content']));prior=json.loads(base64.b64decode(previous['payload']))
            oldmap={(r['version'],r['target']):r for r in prior['releases']};newmap={(r['version'],r['target']):r for r in items}
            if any(newmap.get(k)!=value for k,value in oldmap.items()):raise ValueError('Existing channel entry cannot be removed or changed')
            if base64.b64decode(present['content'])==envelope:print('Channel unchanged');return
        body={'message':'Publish verified signed release index','content':base64.b64encode(envelope).decode()}
        if present:body['sha']=present['sha']
        api(f'repos/{PUBLIC}/contents/channel.json',body)
        print(json.dumps({'publishedPackages':len(items),'channelUpdated':True}))

if __name__=='__main__':main()
