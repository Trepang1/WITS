"""Reconcile complete official profiles and form nonoverlapping step costs."""
import csv,decimal,hashlib,html,json,math,pathlib,re
from replay_support import VM_RUN as HERE
D=decimal.Decimal
def tables(path):
    s=path.read_text(encoding='utf-8');b=re.search(r'<table data-name="exec_methods_total">(.*?)</table>',s,re.S).group(1);methods={}
    for row in re.findall(r'<tr>(.*?)</tr>',b,re.S):
        cols=[html.unescape(re.sub(r'<[^>]+>','',x)).strip()for x in re.findall(r'<td[^>]*>(.*?)</td>',row,re.S)]
        if len(cols)==4:methods[cols[0]]=D(cols[2].replace(',',''))
    def summary(label):
        m=re.search(r'class="category-label">'+label+r'</td>\s*<td[^>]*>([\d.]+)</td>',s);return D(m.group(1))
    ops={};b=re.search(r'<table data-name="exec_operations">(.*?)</table>',s,re.S).group(1)
    for row in re.findall(r'<tr>(.*?)</tr>',b,re.S):
        cols=[html.unescape(re.sub(r'<[^>]+>','',x)).strip()for x in re.findall(r'<td[^>]*>(.*?)</td>',row,re.S)]
        if len(cols)==4:ops[cols[0]]=D(cols[2].replace(',',''))
    return methods,ops,summary('Execution Gas'),summary('IO Gas')
def write_csv(name,rows):
    if not rows:return
    with(HERE/name).open('w',newline='',encoding='utf-8')as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def main():
    totals=[];stages=[];functions=[];operations=[];checks=[]
    labels_ours={
      'statement_and_signatures':'Statement and both Ed25519 signatures',
      'proof_decoding':'Proof decoding and checked point hints',
      'transcript_challenges':'Transcript and H/U generation checks',
      'coefficient_generation':'IPA coefficient generation',
      'scalar_and_msm_input':'Scalar arithmetic and MSM input preparation',
      'polynomial_check':'Polynomial equation MSM',
      'ipa_check':'IPA equation MSM'}
    labels_garg={'signature':'Schnorr signature','authorization':'Three weighted authorization equations','challenge':'FS challenge functions only','select':'Query-position selection','authenticate':'Merkle multiproof authentication','fri_round':'FRI folding and batched hidden openings'}
    for path in sorted((HERE/'results').glob('*/n*/seed*/complete.json')):
        r=json.loads(path.read_text());folder=path.parent;scheme=r['scheme'];n=r['n'];seed=r['seed'];profile=folder/'gas-profile/index.html'
        if not profile.exists():continue
        log=(folder/'profile-overlay.log').read_text();m=re.search(r'\{\s*"Result".*',log,re.S);receipt=json.loads(m.group())['Result'];assert receipt['success']is True and receipt['gas_used']==r['full']['total_charge_gas_units']
        methods,ops,execution,io=tables(profile);assert math.ceil(execution)==r['full']['execution_gas_units'];assert math.ceil(io)==r['full']['io_gas_units']
        assert math.ceil(execution+io)==receipt['gas_used'],'No storage expected in pure verifier'
        module='wtas_vnext'if scheme=='ours'else'garg_vnext_reference'
        labels=labels_ours if scheme=='ours'else labels_garg;used=D(0)
        for function,label in labels.items():
            matches=[v for k,v in methods.items()if k.endswith('::'+module+'::'+function)];assert len(matches)==1,(profile,function)
            value=matches[0];used+=value;stages.append(dict(n=n,seed=seed,scheme=scheme,stage=label,execution_gas=float(value),scope='Disjoint function regions, including child execution; not native-operation categories'))
        residual=execution-used;assert residual>=0
        stages.append(dict(n=n,seed=seed,scheme=scheme,stage='Other execution, framing and intrinsic cost',execution_gas=float(residual),scope='Residual against exact profiler execution; no double counting'))
        for k,v in methods.items():functions.append(dict(n=n,seed=seed,scheme=scheme,function=k,gas_including_children=float(v),additive=False))
        classified={k:D(0)for k in ['Native MSM','Native scalar inversion','Native other scalar arithmetic','Native other group operations','Native Ed25519 verification','Native hashing','Other native operations']}
        for op,value in ops.items():
            if '::'not in op:continue
            if 'multi_scalar_mul_internal'in op:label='Native MSM'
            elif 'scalar_invert'in op:label='Native scalar inversion'
            elif '::ristretto255::scalar_'in op:label='Native other scalar arithmetic'
            elif '::ristretto255::'in op:label='Native other group operations'
            elif '::ed25519::'in op:label='Native Ed25519 verification'
            elif any(x in op for x in ['::hash::','::aptos_hash::']):label='Native hashing'
            else:label='Other native operations'
            classified[label]+=value
        classified['Move instructions, intrinsic and dependency costs']=execution-sum(classified.values());assert min(classified.values())>=0
        operations.extend(dict(n=n,seed=seed,scheme=scheme,category=k,execution_gas=float(v),scope='Exclusive operation categories; separate decomposition from step_gas.csv')for k,v in classified.items())
        reg=r['totals']['registration'];upload=r['totals'].get('proof_upload',{})
        totals.append(dict(n=n,seed=seed,scheme=scheme,execution_gas=float(execution),io_gas=float(io),total_charge_gas=r['full']['total_charge_gas_units'],normal_budget_success=r['normal']['success'],execution_cap=9200,proof_bytes=r['proof_bytes'],verify_transaction_bytes=r['full']['transaction_bytes'],registration_execution_gas=reg['execution_gas_units'],registration_io_gas=reg['io_gas_units'],registration_storage_fee_octas=reg['storage_fee_octas'],registration_total_charge_gas=reg['total_charge_gas_units'],registration_transactions=reg['transactions'],upload_execution_gas=upload.get('execution_gas_units',0),upload_io_gas=upload.get('io_gas_units',0),upload_storage_fee_octas=upload.get('storage_fee_octas',0),upload_total_charge_gas=upload.get('total_charge_gas_units',0),upload_transactions=upload.get('transactions',0),upload_transaction_bytes=upload.get('transaction_bytes',0),complete_honest=True,measurement=r['measurement']))
        valid=dict(n=n,seed=seed,scheme=scheme,success=True,profile_fee_matches_session=True,execution_rounding_matches=True,io_rounding_matches=True,proof_sha256=hashlib.sha256((folder/'proof.bin').read_bytes()).hexdigest(),bundle_sha256=r['bundle_sha256']);checks.append(valid)
        (folder/'validated.json').write_text(json.dumps(valid,indent=2))
    sortkey=lambda r:(r['n'],0 if r['scheme']=='ours'else 1,r['seed'])
    totals.sort(key=sortkey);stages.sort(key=sortkey);functions.sort(key=sortkey);operations.sort(key=sortkey);checks.sort(key=sortkey)
    write_csv('summary.csv',totals);write_csv('step_gas.csv',stages);write_csv('function_gas_nonadditive.csv',functions);write_csv('native_operation_gas.csv',operations)
    (HERE/'validation.json').write_text(json.dumps({'complete_validated_cases':len(checks),'cases':checks,'honest_only':True,'transactions_submitted':False,'statistical_scope':'One deterministic seed per N/scheme; no 30-seed claim.'},indent=2))
    lines=['# Current-vNext official Aptos VM comparison','','Current WTAS proof and both Ed25519 checks are executed in full; Garg is the arbitrary-domain reference with 96 queries and expansion factor16. One honest seed per size. Official CLI9.6.0, framework07490157, unchanged localnet gas prices. These are isolated VM sessions and read-only profiler replays, not committed chain transactions.','','## Complete verification','','| N | Scheme | Execution gas | IO gas | Total charge | Original9200 execution cap | Proof bytes | Verify transaction bytes |','|---:|---|---:|---:|---:|---|---:|---:|']
    for r in totals:lines.append(f"| {r['n']} | {r['scheme']} | {r['execution_gas']:.2f} | {r['io_gas']:.2f} | {r['total_charge_gas']} | {'Pass'if r['normal_budget_success']else 'Exceeded; full diagnostic'} | {r['proof_bytes']} | {r['verify_transaction_bytes']} |")
    lines+=['','## Nonoverlapping verifier steps','','| N | Scheme | Step | Execution gas |','|---:|---|---|---:|']
    for r in stages:lines.append(f"| {r['n']} | {r['scheme']} | {r['stage']} | {r['execution_gas']:.2f} |")
    lines+=['','## Interpretation and boundaries','','- Step regions are disjoint. The function-level inclusive table is nonadditive and must not be summed with these steps. Garg FRI includes its hidden-opening batch checks; the FS column covers challenge functions, with transcript construction in residual cost.','- Registration and proof upload execute before verification and are recorded separately with IO, storage fees and transaction counts. Garg registration trusts the benchmark authority to supply correctly constructed public preprocessing; this is not an on-chain proof of preprocessing correctness.','- Pure verification adds no persistent storage. First upload/registration costs must not be equated with recurring verifier computation.','- Current WTAS includes combiner authentication, unlike frozen v3. Raw current proofs are byte-for-byte identical to the CPU fixtures for the same public deterministic seed.','- Registered proof bases and H/U reject the negligible basis-collision case rather than attempting an outer collision retry. Inner try-and-increment is checked with a64-candidate bound. This finite implementation boundary is explicit.','- Standard Ed25519 signatures are checked by Aptos strict native verification. Edwards proof points retain checked subgroup/encoding conversion to native Ristretto arithmetic.','- Raised-cap diagnostic modifies only the isolated execution ceiling, preserving gas prices and real node schedule. It does not make an over-budget verifier admissible as a single original-budget transaction.','- No claim of matched128-bit security or optimized ECFFT complexity follows from this implementation batch.']
    (HERE/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'Reconciled {len(checks)} complete official VM profiles.')
if __name__=='__main__':main()
