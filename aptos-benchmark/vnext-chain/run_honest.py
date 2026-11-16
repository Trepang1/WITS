"""Current proof honest gate and official VM cost sessions. Never submits txs."""
import argparse,copy,hashlib,json,os,re,subprocess
from public_payload import build,Q
from replay_support import (
    ADDR,API,CLI,EXPORTER,FEATURES_PATH,GAS_PATH,PROFILE,RUNTIME,RUN_ROOT,
    VM_RUN as HERE,bytecode_dir,execution_fee,get,leb,legacy_state,load_environment,schedule_bytes,vec,
)
def invoke(folder,name,cmd,timeout=900):
    p=subprocess.run([str(x)for x in cmd],cwd=RUNTIME,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    (folder/(name+'.log')).write_text(p.stdout)
    m=re.search(r'\{\s*"(?:Result|Error)"',p.stdout)
    value=json.loads(p.stdout[m.start():])if m else {'Error':p.stdout}
    return p.returncode,value
def raw(cells):
    a=[bytes.fromhex(x)if isinstance(x,str)else x for x in cells]
    return 'raw:'+(leb(len(a))+b''.join(vec(x)for x in a)).hex()
def argbytes(a):
    k,v=a.split(':',1)
    if k=='hex':return vec(bytes.fromhex(v))
    if k=='raw':return bytes.fromhex(v)
    return int(v).to_bytes({'u8':1,'u64':8}[k],'little')
def txsize(mod,fn,args):
    payload=b'\x02'+bytes.fromhex(ADDR.zfill(64))+vec(mod.encode())+vec(fn.encode())+b'\x00'+leb(len(args))+b''.join(vec(argbytes(a))for a in args)
    return 32+8+len(payload)+8+8+8+1+99
def export(n,seed):
    folder=HERE/f'results/ours/n{n}/seed{seed:02d}';folder.mkdir(parents=True,exist_ok=True)
    exe=EXPORTER
    fixture=RUN_ROOT/f'cpu-comparison/fixtures/n{n}/seed{seed:02d}.json'
    env=os.environ.copy();env['WTAS_BENCH_FIXTURE']=str(fixture)
    p=subprocess.run([str(exe),str(folder)],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (folder/'export.log').write_text(p.stdout);assert p.returncode==0,p.stdout
    old=RUN_ROOT/f'cpu-comparison/results/ours/n{n}/seed{seed:02d}/proof.bin'
    if old.exists():assert old.read_bytes()==(folder/'proof.bin').read_bytes(),'Exporter modified proof bytes'
    data=json.loads((folder/'public.json').read_text());payload=build(data)
    (folder/'payload.json').write_text(json.dumps(payload,indent=2))
    return folder,data,payload
def measure(n,seed,scheme,env,profile=True):
    mod='wtas_vnext'if scheme=='ours'else'garg_vnext_reference'
    if scheme=='ours':folder,data,payload=export(n,seed)
    else:
        folder=HERE/f'results/garg/n{n}/seed{seed:02d}';folder.mkdir(parents=True,exist_ok=True)
        origin=RUN_ROOT/f'cpu-comparison/results/garg/n{n}/seed{seed:02d}'
        data=json.loads((origin/'public.json').read_text());registry=json.loads((origin/'registry.json').read_text());proof=(origin/'proof.bin').read_bytes()
        for name in ['public.json','registry.json','proof.bin']:(folder/name).write_bytes((origin/name).read_bytes())
        norms=[]
        for j,xs in enumerate(registry['domain']):
            cs=[int.from_bytes(bytes.fromhex(c),'little')for c in registry['denominators'][j]];power=(n>>j)//2-1;layer=[]
            for h in xs:
                x=int.from_bytes(bytes.fromhex(h),'little');a=0
                for c in reversed(cs):a=(a*x+c)%Q
                layer.append(pow(pow(a,power,Q),-1,Q).to_bytes(32,'little').hex())
            norms.extend(layer)
        payload={'norms':norms}
    bytecodes={p.stem:p.read_bytes()for p in bytecode_dir('wits').glob('*.mv')}
    if set(bytecodes) != {'wtas_vnext','vnext_adapter','garg_vnext_reference'}:
        raise RuntimeError('Compile the three benchmark Move modules with build.py first.')
    bundle=hashlib.sha256(b''.join(bytecodes[k]for k in sorted(bytecodes))).hexdigest()
    saved=folder/'complete.json'
    if saved.exists():
        old=json.loads(saved.read_text());assert old['bundle_sha256']==bundle,'Sources changed: preserve and inspect old case'
        if profile:
            from profile_overlay import profile as profile_run
            args=payload['verify_args']if scheme=='ours'else ['hex:'+data[k]for k in ['apk','R','signature_scalar','message']]+[f"u64:{data['total']}"]
            profile_run(folder,folder/'session',mod,'verify_chunked'if n==512 and scheme=='garg'else'verify',args,env,old['full'])
        print('Reuse',scheme,n,seed,flush=True);return old
    session=folder/'session';journal=folder/'operations.json';rows=json.loads(journal.read_text())if journal.exists()else[]
    if not session.exists():
        code,res=invoke(folder,'init',[CLI,'move','sim','init','--path',session,'--network',API,'--network-version',env['snapshot']]);assert code==0,res
        (session/'delta.json').write_text(json.dumps({'code::0x'+ADDR+'::'+k:legacy_state(v)for k,v in bytecodes.items()}))
    def run(name,fn,args,phase,diagnostic=False,profiling=False):
        identity=hashlib.sha256(json.dumps([bundle,fn,args,diagnostic,profiling]).encode()).hexdigest()
        old=next((r for r in rows if r['name']==name),None)
        if old:assert old['argument_sha256']==identity;return old
        before=set(session.glob('[[]*execute*/summary.json'))
        cmd=[CLI,'move','run','--session',session,'--profile',PROFILE,'--url',API,'--function-id','0x'+ADDR+'::'+mod+'::'+fn,'--args',*args,'--max-gas','200000','--gas-unit-price','100','--assume-yes']
        if profiling:cmd+=['--profile-gas','--fold-unique-stack']
        code,result=invoke(folder,name,cmd)
        added=set(session.glob('[[]*execute*/summary.json'))-before
        if len(added)!=1:raise RuntimeError((name,result,code,'no unique official VM summary'))
        summarypath=added.pop();summary=json.loads(summarypath.read_text())['execute_transaction']
        fee=execution_fee(summary,folder/(name+'.log'))
        row=dict(name=name,function=fn,phase=phase,diagnostic=diagnostic,profiling=profiling,argument_sha256=identity,transaction_bytes=txsize(mod,fn,args),success=summary['status']=={'Keep':'Success'},status=summary['status'],summary=str(summarypath.relative_to(HERE)),**fee)
        rows.append(row);journal.write_text(json.dumps(rows,indent=2));print(json.dumps(dict(scheme=scheme,n=n,phase=name,success=row['success'],execution=row['execution_gas_units'])),flush=True)
        if phase!='verification':assert row['success'],row
        return row
    if scheme=='ours':
        run('begin','begin',payload['begin_args'],'registration')
        for i,b in enumerate(payload['registration_batches']):run(f'append{i}','append',[b],'registration')
        args=payload['verify_args'];fn='verify';proofbytes=payload['proof_bytes']
    else:
        run('begin','begin',[f'u64:{n}',f"u64:{data['queries']}",f"u64:{data['threshold']}",f"u64:{registry['registered_weight']}",'hex:'+data['registry_digest'],'hex:'+data['registry_root'],raw(registry['vanishing'])],'registration')
        xs=sum(registry['domain'],[]);ns=payload['norms']
        if n==512:run('domain_reset','reset_domain_chunks',[],'registration')
        for i in range(0,len(xs),128):run(f'domain{i//128}','append_domain_chunk'if n==512 else'append_domain',[raw(xs[i:i+128]),raw(ns[i:i+128])],'registration')
        run('proof_reset','reset_proof',[],'proof_upload')
        cells=[proof[i:i+32]for i in range(0,len(proof),32)]
        for i in range(0,len(cells),256):run(f'upload{i//256}','append_proof',[raw(cells[i:i+256])],'proof_upload')
        args=['hex:'+data[k]for k in ['apk','R','signature_scalar','message']]+[f"u64:{data['total']}"]
        fn='verify_chunked'if n==512 else'verify';proofbytes=len(proof)
    normal=run('verify_normal',fn,args,'verification');full=normal
    if not normal['success']:
        assert normal['status']=={'Keep':{'MiscellaneousError':4030}},normal
        changed=copy.deepcopy(env['gas_schedule'])
        for e in changed['entries']:
            if e['key']=='txn.max_execution_gas':e['val']='1000000000000'
        delta=json.loads((session/'delta.json').read_text());delta['resource::0x1::0x1::gas_schedule::GasScheduleV2']=legacy_state(schedule_bytes(changed));(session/'delta.json').write_text(json.dumps(delta))
        full=run('verify_full',fn,args,'verification',True)
    assert full['success'],full
    if profile:
        from profile_overlay import profile as profile_run
        profile_run(folder,session,mod,fn,args,env,full)
    totals={phase:{'transactions':len(items),**{k:sum(i[k]for i in items)for k in ['total_charge_gas_units','execution_gas_units','io_gas_units','storage_fee_octas','storage_fee_refund_octas','transaction_bytes']}}for phase in ['registration','proof_upload']if(items:=[r for r in rows if r['phase']==phase])}
    row=dict(scheme=scheme,n=n,seed=seed,bundle_sha256=bundle,normal=normal,full=full,proof_bytes=proofbytes,totals=totals,measurement='official Aptos Move VM session, no committed transaction',snapshot=env['snapshot'],honest_only=True,current_vnext=scheme=='ours',security_alignment='research parameters, not matched-128-bit certification')
    saved.write_text(json.dumps(row,indent=2));return row
def main():
    p=argparse.ArgumentParser();p.add_argument('--n',type=int,nargs='+',default=[32]);p.add_argument('--seed',type=int,default=0);p.add_argument('--schemes',nargs='+',choices=['ours','garg'],default=['ours','garg']);p.add_argument('--no-profile',action='store_true');a=p.parse_args()
    env=load_environment()
    for n in a.n:
        for scheme in a.schemes:measure(n,a.seed,scheme,env,not a.no_profile)
    assert get(GAS_PATH)['data']==env['gas_schedule']
    assert get(FEATURES_PATH)['data']==env['features']
    (HERE/'NODE_AFTER.json').write_text(json.dumps({'node':get(),'gas_schedule_unchanged':True,'transactions_submitted':False},indent=2))
if __name__=='__main__':main()
