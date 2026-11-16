"""Complete Das verification in the pinned official Aptos VM; never submits txs."""
from pathlib import Path
import argparse,copy,csv,hashlib,json,math,re,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OLD=ROOT/'aptos-benchmark/vnext-chain'
sys.path.insert(0,str(OLD))
import run_honest as helper
import collect_results as costs
import profile_overlay as profiler
from replay_support import ADDR,API,CLI,FEATURES_PATH,GAS_PATH,PROFILE,RUNTIME,RUN_ROOT,VM_RUN,bytecode_dir,execution_fee,get,load_environment
OUT=RUN_ROOT/'das-rust/chain-results'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def invoke(folder,name,argv,timeout=180):
    p=subprocess.run([str(x) for x in argv],cwd=RUNTIME,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
    (folder/(name+'.log')).write_text(p.stdout)
    match=re.search(r'\{\s*"(?:Result|Error)"',p.stdout)
    result=json.loads(p.stdout[match.start():]) if match else {'Error':p.stdout}
    return p.returncode,result

def measure(n,env):
    folder=OUT/f'n{n}/seed00';folder.mkdir(parents=True,exist_ok=True)
    complete=folder/'complete.json'
    bytecode=bytecode_dir('das')/'das_reference.mv'
    cpu=RUN_ROOT/f'das-rust/results/das/n{n}/seed00'
    public=json.loads((cpu/'move-params.json').read_text())
    wire=(cpu/'core-package.bin').read_bytes()
    identity={'bytecode_sha256':sha(bytecode),'cpu_package_sha256':sha(cpu/'core-package.bin')}
    if complete.exists():
        old=json.loads(complete.read_text());assert all(old[k]==v for k,v in identity.items());return old
    session=folder/'session'
    code,result=invoke(folder,'init',[CLI,'move','sim','init','--path',session,'--network',API,'--network-version',env['snapshot']])
    assert code==0,result
    (session/'delta.json').write_text(json.dumps({'code::0x'+ADDR+'::das_reference':helper.legacy_state(bytecode.read_bytes())}))
    def run(name,fn,args):
        before=set(session.glob('[[]*execute*/summary.json'))
        cmd=[CLI,'move','run','--session',session,'--profile',PROFILE,'--url',API,'--function-id','0x'+ADDR+'::das_reference::'+fn,
            '--args',*args,'--max-gas','200000','--gas-unit-price','100','--assume-yes']
        code,value=invoke(folder,name,cmd)
        added=set(session.glob('[[]*execute*/summary.json'))-before
        assert len(added)==1,(name,code,value)
        path=added.pop();value=json.loads(path.read_text())['execute_transaction']
        row={'success':value['status']=={'Keep':'Success'},'status':value['status'],
             'transaction_bytes':helper.txsize('das_reference',fn,args),**execution_fee(value,folder/(name+'.log'))}
        (folder/(name+'.json')).write_text(json.dumps(row,indent=2))
        return row
    registration=run('registration','register',[f'u64:{n}',f"u64:{public['threshold']}",helper.raw(public['points'])])
    assert registration['success'],registration
    args=['hex:'+public['message_hex'],'hex:'+wire.hex()]
    normal=run('verify_normal','verify',args);full=normal
    if not normal['success']:
        assert normal['status']=={'Keep':{'MiscellaneousError':4030}},normal
        changed=copy.deepcopy(env['gas_schedule'])
        for entry in changed['entries']:
            if entry['key']=='txn.max_execution_gas':entry['val']=str(int(entry['val'])*8)
        delta=json.loads((session/'delta.json').read_text())
        delta['resource::0x1::0x1::gas_schedule::GasScheduleV2']=helper.legacy_state(helper.schedule_bytes(changed))
        (session/'delta.json').write_text(json.dumps(delta))
        full=run('verify_full','verify',args)
    assert full['success'],full
    prof=profiler.profile(folder,session,'das_reference','verify',args,env,full)
    methods,ops,execution,io=costs.tables(prof/'index.html')
    assert math.ceil(execution)==full['execution_gas_units'] and math.ceil(io)==full['io_gas_units']
    assert math.ceil(execution+io)==full['total_charge_gas_units']
    events=json.loads((folder/'profile-overlay-requests.json').read_text())
    assert not any(e['method']=='POST' and '/transactions' in e['path'] for e in events)
    stages=[];used=0
    for function in ['signature','key_and_complement','binary','inner_product','degree_and_weight','decode','challenge']:
        values=[v for k,v in methods.items() if k.endswith('::das_reference::'+function)]
        assert len(values)==1,(function,methods)
        used+=values[0];stages.append({'n':n,'stage':function,'execution_gas':str(values[0])})
    stages.append({'n':n,'stage':'other framing and parameter processing','execution_gas':str(execution-used)})
    assert execution-used>=0
    row={'n':n,'seed':0,'scheme':'das','implementation':'Rust prover / native BLS12-381 Move verifier',
      **identity,'execution_gas':str(execution),'io_gas':str(io),'total_charge_gas':full['total_charge_gas_units'],
      'normal_budget_success':normal['success'],'execution_cap':9200,'proof_bytes':384,'core_package_bytes':536,
      'verify_transaction_bytes':full['transaction_bytes'],'registration':registration,'normal':normal,'full':full,
      'stage_gas':stages,'complete_honest':True,'transactions_submitted':False,
      'measurement':'official Aptos VM complete verifier; independent official profiler; same pinned gas prices',
      'pairing_api_calls':9,'pairing_input_pairs':15}
    complete.write_text(json.dumps(row,indent=2))
    print(json.dumps({'n':n,'scheme':'das','execution_gas':str(execution),'io_gas':str(io),'normal_pass':normal['success']}),flush=True)
    return row

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sizes',nargs='+',type=int,default=[32,64,128,256,512]);parser.add_argument('--audit-unfolded',action='store_true');args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    env=load_environment()
    record={'reset':False,'transactions_submitted':False}
    try:
        (OUT/'ENVIRONMENT.json').write_text(json.dumps(env,indent=2))
        for n in args.sizes:measure(n,env)
        rows=[json.loads(p.read_text()) for p in sorted(OUT.glob('n*/seed00/complete.json'),key=lambda p:int(p.parents[1].name[1:]))]
        fields=['n','seed','scheme','execution_gas','io_gas','total_charge_gas','normal_budget_success','execution_cap','proof_bytes','core_package_bytes','verify_transaction_bytes','complete_honest','measurement']
        with (OUT/'summary.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
        with (OUT/'step_gas.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['n','stage','execution_gas']);writer.writeheader();writer.writerows([v for r in rows for v in r['stage_gas']])
        previous=VM_RUN/'summary.csv'
        old=list(csv.DictReader(previous.open())) if previous.is_file() else []
        allrows=old+rows;cols=list(dict.fromkeys(k for r in allrows for k in r if k in fields))
        with (OUT/'three_scheme_summary.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=cols,extrasaction='ignore');writer.writeheader();writer.writerows(sorted(allrows,key=lambda r:(int(r['n']),r['scheme'])))
        if args.audit_unfolded:
            import audit_unfolded
            audit_unfolded.audit()
        assert get(GAS_PATH)['data']==env['gas_schedule'] and get(FEATURES_PATH)['data']==env['features']
        record.update({'complete':True,'cases':len(rows),'gas_schedule_unchanged':True,'features_unchanged':True})
    except Exception as exc:
        record['error']=repr(exc);raise
    finally:
        (OUT/'lifecycle.json').write_text(json.dumps(record,indent=2))

if __name__=='__main__':main()
