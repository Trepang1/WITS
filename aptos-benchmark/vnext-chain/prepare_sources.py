"""Create isolated exact-current exporter and Move package; never edit baselines."""
import hashlib,json,pathlib,shutil
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parent
src=ROOT/'cpu-comparison/rust/src/ours.rs'
s=src.read_text(encoding='utf-8')
s=s.replace('    let mut reg_bytes = vec![];','    let mut reg_bytes = vec![];\n    let mut pops = vec![];')
s=s.replace('        assert_eq!(response * G, dp + e * pk[i]);','        assert_eq!(response * G, dp + e * pk[i]);\n        pops.push(json!({"D":hex::encode(enc(&dp)),"response":hex::encode(response.to_bytes())}));')
needle='    fs::write(format!("{out}/proof.bin"), &bytes).unwrap();'
export='''
    let (_,hh)=transcript(&p,&reg,&v);
    let mut replay=transcript(&p,&reg,&v).0;
    replay.p(b"A",&proof.a); replay.c(b"lambda_key"); replay.p(b"S",&proof.s);
    replay.c(b"y");replay.c(b"z");replay.p(b"T1",&proof.t1);replay.p(b"T2",&proof.t2);replay.c(b"x");
    let uu=evaluated(&mut replay,&proof,&p,hh);
    fs::write(format!("{out}/public.json"),serde_json::to_vec_pretty(&json!({
      "n":n,"threshold":threshold,"total":total,"weights":reg.w,
      "pk":reg.pk.iter().map(|p|hex::encode(enc(p))).collect::<Vec<_>>(),
      "g":p.g.iter().map(|p|hex::encode(enc(p))).collect::<Vec<_>>(),
      "h":p.h.iter().map(|p|hex::encode(enc(p))).collect::<Vec<_>>(),
      "pops":pops,"registry_digest":hex::encode(reg.digest),
      "registry_bytes":hex::encode(&reg_bytes),"statement":hex::encode(statement(&reg,&v).0),
      "H":hex::encode(enc(&hh)),"U":hex::encode(enc(&uu)),
      "message":hex::encode(&v.m),"aggregate_key":hex::encode(enc(&v.k)),
      "signature":hex::encode(&signature),"proof":hex::encode(&bytes),
      "combiner_pk":hex::encode(enc(&combiner_pk)),"combiner_signature":hex::encode(&auth),
      "combiner_message":hex::encode(&package),"protocol_version":"current-vNext-20261026"
    })).unwrap()).unwrap();
'''
assert needle in s
s=s.replace(needle,needle+export)
(HERE/'rust/src').mkdir(parents=True,exist_ok=True)
(HERE/'rust/src/main.rs').write_text(s,encoding='utf-8')
(HERE/'rust/Cargo.toml').write_text('''[package]
name="wtas-vnext-chain-export"
version="0.1.0"
edition="2021"
[workspace]
[dependencies]
curve25519-dalek={version="=4.1.3",features=["rand_core","digest"]}
rand="=0.8.5"
sha2="=0.10.9"
serde_json="=1.0.145"
hex="=0.4.3"
''',encoding='utf-8')
(HERE/'move/sources').mkdir(parents=True,exist_ok=True)
adapter=ROOT/'v3/optimized/sources/edwards_adapter.move'
a=adapter.read_text().replace('bench::edwards_adapter','bench::vnext_adapter').replace('b"WTAS/Edwards/hash-to-group/v1"','b"WTAS/CPU/Edwards/HashToGroup/v1"')
(HERE/'move/sources/vnext_adapter.move').write_text(a)
# Garg equations/FRI/Merkle code retained, with registered total replacing old
# incidental n*100 fixture bound. The arbitrary-domain reference is explicit.
garg=ROOT/'v3/optimized/sources/garg_honest_v2.move'
g=garg.read_text().replace('bench::garg_honest_v2','bench::garg_vnext_reference')
g=g.replace('n: u64, count: u64, threshold: u64, registry_digest:', 'n: u64, count: u64, threshold: u64, registered_total: u64, registry_digest:')
g=g.replace('n: u64, count: u64, threshold: u64, registry_digest:', 'n: u64, count: u64, threshold: u64, registered_total: u64, registry_digest:')
g=g.replace('threshold <= n*100','threshold <= registered_total').replace('Parameters { n, count, threshold, registry_digest','Parameters { n, count, threshold, registered_total, registry_digest')
g=g.replace('verify_inner(p.n,p.count,p.threshold,','verify_inner(p.n,p.count,p.threshold,p.registered_total,')
g=g.replace('verify_inner(n:u64,count:u64,threshold:u64,digest:', 'verify_inner(n:u64,count:u64,threshold:u64,registered_total:u64,digest:')
g=g.replace('total<=n*100','total<=registered_total')
(HERE/'move/sources/garg_vnext_reference.move').write_text(g)
sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [src,adapter,garg]}
(HERE/'SOURCE_PROVENANCE.json').write_text(json.dumps({'input_sha256':sources,'note':'Exporter adds only public output; no RNG draws or protocol changes. Garg registered_total replaces incidental <=100*N fixture bound.'},indent=2))
print('Isolated exporter and reusable Move sources prepared.')
