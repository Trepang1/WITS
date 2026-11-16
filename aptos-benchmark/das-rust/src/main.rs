mod poly;
mod protocol;
mod research_rng;

use blstrs::{G1Affine,G2Affine,Scalar};
use group::Curve;
use protocol::{Crs,Registry,Signature};
use research_rng::ResearchRng;
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{env,fs,path::Path,time::Instant};

fn ms(t:Instant)->f64 {t.elapsed().as_secs_f64()*1000.0}
fn digest(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
fn g1(point:G1Affine)->String {hex::encode(point.to_compressed())}
fn g2(point:G2Affine)->String {hex::encode(point.to_compressed())}
fn scalar(value:Scalar)->String {hex::encode(value.to_bytes_be())}
fn proof_bytes(s:&Signature)->Vec<u8> {
    let mut out=Vec::with_capacity(384);
    out.extend(s.b_tau.to_compressed());out.extend(s.b_neg_tau.to_compressed());
    for point in [s.q_tau,s.r_tau,s.q_b,s.p_tau,s.agg_pk_b] {out.extend(point.to_compressed());}
    out
}
fn package_bytes(s:&Signature)->Vec<u8> {
    let mut out=Vec::with_capacity(536);
    out.extend(s.agg_pk.to_compressed());out.extend(s.agg_sig.to_compressed());
    out.extend(s.weight.to_le_bytes());out.extend(proof_bytes(s));out
}
fn decode(bytes:&[u8])->Signature {
    assert_eq!(bytes.len(),536);
    let p1=|at:usize|Option::<G1Affine>::from(G1Affine::from_compressed(bytes[at..at+48].try_into().unwrap())).expect("canonical subgroup G1");
    let p2=|at:usize|Option::<G2Affine>::from(G2Affine::from_compressed(bytes[at..at+96].try_into().unwrap())).expect("canonical subgroup G2");
    Signature {agg_pk:p1(0),agg_sig:p2(48),weight:u64::from_le_bytes(bytes[144..152].try_into().unwrap()),
      b_tau:p1(152),b_neg_tau:p2(200),q_tau:p1(296),r_tau:p1(344),q_b:p1(392),p_tau:p1(440),agg_pk_b:p1(488)}
}

fn check_oracle(crs:&Crs,reg:&Registry,sig:&Signature,shares:&[blstrs::G2Projective],msg:&[u8],wire:&[u8],oracle:&Value) {
    let check=|path:&str,actual:String,expected:&Value|assert_eq!(actual,expected.as_str().unwrap(),"oracle mismatch: {path}");
    check("tau",scalar(crs.tau),&oracle["crs_scalars"]["tau"]);
    check("beta",scalar(crs.beta),&oracle["crs_scalars"]["beta"]);
    check("h_scalar",scalar(crs.h_scalar),&oracle["crs_scalars"]["h_f"]);
    check("omega",scalar(crs.omega),&oracle["crs"]["domain_generator"]);
    check("fft_coset",scalar(crs.fft_coset),&oracle["crs"]["fft_coset"]);
    check("pComm",g1(reg.p_comm),&oracle["registry"]["pComm"]);
    check("wTau",g1(reg.w_tau),&oracle["registry"]["wTau"]);
    check("hash_to_g2",g2(protocol::hash_message(msg)),&oracle["hash_to_g2"]);
    for (i,key) in reg.sk.iter().enumerate(){check("secret_key",scalar(*key),&oracle["secret_keys"][i]);}
    for (i,point) in reg.q_tau.iter().enumerate(){check("qTau",g1(*point),&oracle["registry"]["qTaus"][i]);}
    for (i,point) in shares.iter().enumerate(){check("share",g2(point.to_affine()),&oracle["shares"][i]);}
    check("xi",scalar(protocol::fs_challenge(reg,sig.b_tau,sig.agg_pk,sig.weight)),&oracle["signature"]["xi"]);
    check("package",hex::encode(wire),&oracle["package_hex"]);
}

fn main() {
    let out_arg=env::args().nth(1).expect("output directory");
    let out=Path::new(&out_arg);fs::create_dir_all(out).unwrap();
    let fixture_path=env::var("WTAS_BENCH_FIXTURE").expect("common fixture path");
    let fixture_bytes=fs::read(&fixture_path).unwrap();
    let fixture:Value=serde_json::from_slice(&fixture_bytes).unwrap();
    let n=fixture["n"].as_u64().unwrap() as usize;
    let k=fixture["k"].as_u64().unwrap() as usize;
    let weights:Vec<u64>=fixture["weights"].as_array().unwrap().iter().map(|w|w.as_u64().unwrap()).collect();
    let selected:Vec<usize>=fixture["participation_bits"].as_array().unwrap().iter().enumerate().filter_map(|(i,b)|match b.as_u64().unwrap(){0=>None,1=>Some(i),_=>panic!("nonbinary fixture")}).collect();
    assert_eq!(weights.len(),n);assert_eq!(selected.len(),k);
    let total:u64=selected.iter().map(|i|weights[*i]).sum();
    let threshold=fixture["threshold"].as_u64().unwrap();
    assert_eq!(total,fixture["selected_weight"].as_u64().unwrap());
    assert!(threshold>0 && total>=threshold && weights.iter().all(|w|*w>0));
    assert!(weights.iter().sum::<u64>()<=u32::MAX as u64);
    let msg=hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
    let mut seed=b"Das23/local-CRS/v1".to_vec();
    seed.extend(hex::decode(fixture["rng_seed_hex"].as_str().unwrap()).unwrap());
    let mut rng=ResearchRng::new(seed);
    let now=Instant::now();let crs=Crs::generate(n,&mut ||rng.scalar());let setup_ms=ms(now);
    eprintln!("setup n={n}: {setup_ms:.3} ms");
    let mut h=Sha256::new();h.update(b"Das23/public-key-seeds/v1");
    for key in fixture["public_benchmark_key_seeds"].as_array().unwrap(){h.update(hex::decode(key.as_str().unwrap()).unwrap());}
    let mut rng=ResearchRng::new(h.finalize().to_vec());
    let now=Instant::now();let mut reg=Registry::keygen(&crs,&weights,&mut ||rng.scalar());let keygen_ms=ms(now);
    eprintln!("keygen n={n}: {keygen_ms:.3} ms");
    let now=Instant::now();reg.preprocess(&crs);let preprocessing_ms=ms(now);
    eprintln!("preprocess n={n}: {preprocessing_ms:.3} ms");
    let mut signer_times=Vec::with_capacity(k);let mut signatures=Vec::with_capacity(k);
    let now_all=Instant::now();
    for index in &selected {let now=Instant::now();signatures.push(protocol::sign(&msg,reg.sk[*index]));signer_times.push(ms(now));}
    let signing_ms=ms(now_all);
    let now=Instant::now();let hashed=protocol::hash_message(&msg);
    for (signature,index) in signatures.iter().zip(&selected) {
        let received=Option::<G2Affine>::from(G2Affine::from_compressed(&signature.to_affine().to_compressed())).unwrap();
        assert!(protocol::check_share(&crs,hashed,received.into(),reg.pk[*index]));
    }
    let share_validation_ms=ms(now);
    let now=Instant::now();let sig=protocol::combine(&crs,&reg,&selected,&signatures);let combine_with_proof_ms=ms(now);
    let now=Instant::now();let wire=package_bytes(&sig);let proof=proof_bytes(&sig);let serialization_ms=ms(now);
    assert_eq!(wire.len(),536);assert_eq!(proof.len(),384);
    let now=Instant::now();let decoded=decode(&wire);let accepted=protocol::verify(&crs,&reg,&msg,&decoded,threshold);let verification_ms=ms(now);
    assert!(accepted && decoded.weight==total);assert_eq!(wire,package_bytes(&decoded));
    let mut oracle_checked=false;
    if let Ok(path)=env::var("DAS_ORACLE_JSON") {
        let oracle:Value=serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        check_oracle(&crs,&reg,&sig,&signatures,&msg,&wire,&oracle);oracle_checked=true;
    }
    let mut frozen_equal=false;
    if let Ok(path)=env::var("DAS_EXPECTED_GO_PACKAGE") {assert_eq!(wire,fs::read(path).unwrap(),"Rust/Go output differs");frozen_equal=true;}
    fs::write(out.join("core-package.bin"),&wire).unwrap();fs::write(out.join("authorization-proof.bin"),&proof).unwrap();
    let params=json!([g1(reg.p_comm),g1(reg.w_tau),g2(crs.g2_beta),g2(crs.h2),g2(crs.h_tau),g2(crs.g2_tau),g2(crs.v_h_tau)]);
    fs::write(out.join("move-params.json"),serde_json::to_vec_pretty(&json!({"n":n,"threshold":threshold,"message_hex":hex::encode(&msg),"points":params,"source_package_sha256":digest(&wire)})).unwrap()).unwrap();
    fs::write(out.join("interop.json"),serde_json::to_vec_pretty(&json!({"honest_pass":true,"oracle_checked":oracle_checked,"frozen_go_package_equal":frozen_equal,"package_sha256":digest(&wire),"fixture_sha256":digest(&fixture_bytes)})).unwrap()).unwrap();
    let initialization_ms=setup_ms+keygen_ms+preprocessing_ms;
    let aggregation_and_proving_ms=share_validation_ms+combine_with_proof_ms+serialization_ms;
    let signer_mean_ms=signer_times.iter().sum::<f64>()/(k as f64);
    let result=json!({"scheme":"das","implementation":"Rust/blstrs","protocol_version":"Das23(author-corrected)-Rust-port-v1",
        "n":n,"k":k,"seed":fixture["seed"],"honest_pass":accepted,"setup_ms":setup_ms,"keygen_ms":keygen_ms,
        "preprocessing_ms":preprocessing_ms,"initialization_ms":initialization_ms,"signing_ms":signing_ms,"signer_mean_ms":signer_mean_ms,
        "signer_max_ms":signer_times.iter().copied().fold(0.0,f64::max),"coordination_ms":null,"share_validation_ms":share_validation_ms,
        "aggregation_core_ms":null,"proving_ms":null,"combine_with_proof_ms":combine_with_proof_ms,"serialization_ms":serialization_ms,
        "aggregation_and_proving_ms":aggregation_and_proving_ms,"aggregation_excluding_share_checks_ms":aggregation_and_proving_ms-share_validation_ms,
        "verification_ms":verification_ms,"signature_verification_ms":null,"proof_verification_ms":null,
        "online_total_ms":signing_ms+aggregation_and_proving_ms+verification_ms,"proof_bytes":proof.len(),"core_package_bytes":wire.len(),
        "registry_material_bytes":null,"fixture_sha256":digest(&fixture_bytes),"core_package_sha256":digest(&wire),
        "pairing_api_calls":9,"pairing_input_pairs":15,"threading":"single process, pinned CPU, no application parallelism",
        "network_timing":false,"setup_basis":"full local CRS arithmetic; no distributed ceremony timing",
        "aggregation_basis":"share checks plus full integrated author combine/proof and serialization",
        "verification_basis":"canonical subgroup-checked decode plus full signature/authorization/threshold verification"});
    fs::write(out.join("result.json"),serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    println!("{}",json!({"n":n,"k":k,"honest_pass":accepted,"verification_ms":verification_ms,"proof_bytes":proof.len(),"frozen_go_package_equal":frozen_equal}));
}
