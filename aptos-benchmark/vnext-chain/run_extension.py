"""Replay regenerated verifier sessions under isolated 1/2/4/8x execution ceilings."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import copy
import csv
import hashlib
import json
import math
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'aptos-benchmark/vnext-chain'))
from replay_support import (ADDR, API, CLI, FEATURES_PATH, GAS_PATH, PROFILE, RUNTIME,
                            RUN_ROOT, VM_RUN as SOURCE, execution_fee, get, load_environment)
import run_honest as runner
import profile_overlay as profiler
import collect_results as collector

OUT = RUN_ROOT/'extension-budget'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(folder, name, argv, timeout=180):
    process = subprocess.Popen([str(x) for x in argv], cwd=RUNTIME,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        stdout, _ = process.communicate(timeout=20)
        (folder/(name+'.log')).write_text(stdout)
        raise
    (folder/(name+'.log')).write_text(stdout)
    # Profile configuration is read by the CLI, never printed in evidence.
    safe_argv = [str(x) for x in argv]
    if '--args' in safe_argv:
        start = safe_argv.index('--args')+1
        end = safe_argv.index('--max-gas')
        safe_argv[start:end] = ['<public arguments stored in fixture; sha256 recorded>']
    (folder/(name+'.command.json')).write_text(json.dumps({'argv':safe_argv,'exit_code':process.returncode},indent=2))
    match = re.search(r'\{\s*"(?:Result|Error)"', stdout)
    value = json.loads(stdout[match.start():]) if match else {'Error':stdout}
    return process.returncode, value


def execute(env,sizes):
    profiler.invoke = invoke
    data = list(csv.DictReader((SOURCE/'summary.csv').open()))
    scale = int(next(e['val'] for e in env['gas_schedule']['entries'] if e['key']=='txn.gas_unit_scaling_factor'))
    base = int(next(e['val'] for e in env['gas_schedule']['entries'] if e['key']=='txn.max_execution_gas'))
    assert base/scale == 9200
    rows = []
    attempts = []
    for n in sizes:
        for scheme in ['ours', 'garg']:
            original = SOURCE/f'results/{scheme}/n{n}/seed00'
            case = OUT/f'results/{scheme}/n{n}/seed00'
            case.mkdir(parents=True)
            module = 'wtas_vnext' if scheme=='ours' else 'garg_vnext_reference'
            function = 'verify_chunked' if scheme=='garg' and n==512 else 'verify'
            if scheme=='ours':
                args = json.loads((original/'payload.json').read_text())['verify_args']
            else:
                public = json.loads((original/'public.json').read_text())
                args = ['hex:'+public[k] for k in ['apk','R','signature_scalar','message']]+[f"u64:{public['total']}"]
            proof = original/'proof.bin'
            assert proof.read_bytes() == (RUN_ROOT/f'cpu-comparison/results/{scheme}/n{n}/seed00/proof.bin').read_bytes()
            argument_hash = hashlib.sha256(json.dumps(args).encode()).hexdigest()
            successes = {}
            for multiplier in [1,2,4,8]:
                folder = case/f'cap-{multiplier}x'
                folder.mkdir()
                session = folder/'session'
                session.mkdir()
                shutil.copy2(original/'session/config.json', session/'config.json')
                delta = json.loads((original/'session/delta.json').read_text())
                schedule = copy.deepcopy(env['gas_schedule'])
                for entry in schedule['entries']:
                    if entry['key']=='txn.max_execution_gas': entry['val']=str(base*multiplier)
                assert [(e['key'],e['val']) for e in schedule['entries'] if e['key']!='txn.max_execution_gas'] == [(e['key'],e['val']) for e in env['gas_schedule']['entries'] if e['key']!='txn.max_execution_gas']
                delta['resource::0x1::0x1::gas_schedule::GasScheduleV2'] = runner.legacy_state(runner.schedule_bytes(schedule))
                (session/'delta.json').write_text(json.dumps(delta))
                command = [CLI,'move','run','--session',session,'--profile',PROFILE,'--url',API,
                    '--function-id','0x'+ADDR+'::'+module+'::'+function,'--args',*args,
                    '--max-gas','200000','--gas-unit-price','100','--assume-yes']
                code, value = invoke(folder,'verify',command)
                summaries = list(session.glob('[[]*execute*/summary.json'))
                assert len(summaries)==1, (scheme,n,multiplier,code,value)
                summary = json.loads(summaries[0].read_text())['execute_transaction']
                success = summary['status']=={'Keep':'Success'}
                if not success:
                    assert summary['status']=={'Keep':{'MiscellaneousError':4030}}, summary
                row = {'scheme':scheme,'n':n,'seed':0,'multiplier':multiplier,
                    'execution_cap':base*multiplier//scale,'success':success,
                    'status':summary['status'],'argument_sha256':argument_hash,
                    **execution_fee(summary,folder/'verify.log')}
                attempts.append(row)
                (folder/'result.json').write_text(json.dumps(row,indent=2))
                successes[multiplier]=success
                print(json.dumps({'stage':'verify','scheme':scheme,'n':n,'cap':multiplier,'success':success,'charged_exec':row['execution_gas_units']}),flush=True)
                if multiplier==8:
                    assert success
                    eight_session = session
                    eight_result = row
            profile = profiler.profile(case,eight_session,module,function,args,env,eight_result)
            _,_,execution,io = collector.tables(profile/'index.html')
            assert math.ceil(execution)==eight_result['execution_gas_units']
            assert math.ceil(io)==eight_result['io_gas_units']
            assert math.ceil(execution+io)==eight_result['total_charge_gas_units']
            recorded = next(r for r in data if r['scheme']==scheme and int(r['n'])==n)
            assert abs(float(execution)-float(recorded['execution_gas']))<1e-7
            assert abs(float(io)-float(recorded['io_gas']))<1e-7
            successful = [r for r in attempts if r['n']==n and r['scheme']==scheme and r['success']]
            assert len({(r['execution_gas_units'],r['io_gas_units'],r['total_charge_gas_units']) for r in successful})==1
            events=json.loads((case/'profile-overlay-requests.json').read_text())
            assert not any(e['method']=='POST' and '/transactions' in e['path'] for e in events)
            rows.append({'n':n,'seed':0,'scheme':'WITS' if scheme=='ours' else 'Garg reference',
                'execution_gas':str(execution),'io_gas':str(io),
                'total_charge_gas':eight_result['total_charge_gas_units'],
                'proof_bytes':proof.stat().st_size,'proof_sha256':sha(proof),
                **{f'pass_{m}x':successes[m] for m in [1,2,4,8]},
                'same_full_cost_at_all_successful_budgets':True,'equals_reference_session_cost':True})
    for name,collection in [('summary',rows),('attempts',attempts)]:
        with (OUT/(name+'.csv')).open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(collection[0]));writer.writeheader();writer.writerows(collection)
    (OUT/'results.json').write_text(json.dumps({'cases':rows,'attempts':attempts,
        'actual_aip146_eligibility_test':False,'transactions_submitted':False,
        'scope':'Current vNext complete verifiers; one saved honest proof per size; official VM and independent official profiler',
        'only_isolated_execution_cap_changed':True},indent=2))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes',type=int,nargs='+',choices=(256,512),default=[256,512])
    args=parser.parse_args()
    assert not (OUT/'results').exists(), 'Preserve earlier evidence'
    env=load_environment()
    OUT.mkdir(parents=True,exist_ok=True)
    baseline = [SOURCE/'summary.csv',SOURCE/'ENVIRONMENT.json']
    for n in args.sizes:
        for scheme in ['ours','garg']:
            case=SOURCE/f'results/{scheme}/n{n}/seed00'
            baseline += [case/'session/config.json',case/'session/delta.json',case/'proof.bin',case/'complete.json']
    before = {str(p.relative_to(RUN_ROOT)):sha(p) for p in baseline}
    (OUT/'baseline-hashes.json').write_text(json.dumps(before,indent=2))
    lifecycle = {'reset':False,'transactions_submitted':False}
    try:
        lifecycle.update({'gas_pin_matches':True,'features_pin_matches':True,'node_before':get()})
        execute(env,args.sizes)
        assert get(GAS_PATH)['data']==env['gas_schedule'] and get(FEATURES_PATH)['data']==env['features']
        assert all(sha(RUN_ROOT/p)==digest for p,digest in before.items())
        lifecycle.update({'complete':True,'baseline_unchanged':True,'node_schedule_unchanged':True})
    except Exception as error:
        lifecycle['error']=repr(error)
        raise
    finally:
        (OUT/'lifecycle.json').write_text(json.dumps(lifecycle,indent=2))
        print(json.dumps({'stage':'complete','complete':lifecycle.get('complete',False)}),flush=True)


if __name__=='__main__':main()
