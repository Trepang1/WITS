//! Serial CPU phase timings for the existing arbitrary-domain Garg WTS reference.
//! Hidden polynomial construction takes PUBLIC group elements, never signing secrets.
//! This is not an optimized ECFFT prover or a production signing client.
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint as P},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use garg_ecfft_field_probe::{domain, Domain, F};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    time::Instant,
};

fn fb(x: F) -> [u8; 32] {
    let mut b = [0; 32];
    let v = x.into_bigint().to_bytes_le();
    b[..v.len()].copy_from_slice(&v);
    b
}
fn sc(x: F) -> Scalar {
    Scalar::from_canonical_bytes(fb(x)).unwrap()
}
fn pf(x: &[u8]) -> F {
    assert_eq!(x.len(), 32);
    let f = F::from_le_bytes_mod_order(x);
    assert_eq!(fb(f).as_slice(), x);
    f
}
fn pg(x: &[u8]) -> P {
    CompressedRistretto(x.try_into().unwrap())
        .decompress()
        .unwrap()
}
fn pb(x: P) -> [u8; 32] {
    x.compress().to_bytes()
}
fn msm(c: &[F], p: &[P]) -> P {
    P::vartime_multiscalar_mul(c.iter().copied().map(sc), p)
}
fn hash(x: &[u8]) -> [u8; 32] {
    Sha256::digest(x).into()
}
fn hf(x: &[u8]) -> F {
    F::from_le_bytes_mod_order(&Sha512::digest(x))
}
fn u64b(x: usize) -> [u8; 8] {
    (x as u64).to_le_bytes()
}
fn append(v: &mut Vec<u8>, x: &[u8]) {
    v.extend_from_slice(x);
}
fn challenge(t: &mut Vec<u8>, label: u8) -> F {
    t.push(label);
    let x = hf(t);
    append(t, &fb(x));
    x
}
fn eval(a: &[F], x: F) -> F {
    a.iter().rev().fold(F::zero(), |r, c| r * x + c)
}
fn ep(a: &[P], x: F) -> P {
    let mut c = vec![];
    let mut y = F::one();
    for _ in a {
        c.push(y);
        y *= x;
    }
    msm(&c, a)
}
fn mul(a: &[F], b: &[F]) -> Vec<F> {
    let mut c = vec![F::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            c[i + j] += *x * y;
        }
    }
    c
}
fn pmul(a: &[P], b: &[F]) -> Vec<P> {
    let mut c = vec![P::identity(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            c[i + j] += x * sc(*y);
        }
    }
    c
}
fn div(mut a: Vec<F>, z: &[F]) -> (Vec<F>, Vec<F>) {
    let mut q = vec![F::zero(); a.len() - z.len() + 1];
    for i in (0..q.len()).rev() {
        q[i] = a[i + z.len() - 1];
        for j in 0..z.len() {
            a[i + j] -= q[i] * z[j];
        }
    }
    a.truncate(z.len() - 1);
    (q, a)
}
fn pdiv(mut a: Vec<P>, z: &[F]) -> (Vec<P>, Vec<P>) {
    let mut q = vec![P::identity(); a.len() - z.len() + 1];
    for i in (0..q.len()).rev() {
        q[i] = a[i + z.len() - 1];
        for j in 0..z.len() {
            a[i + j] -= q[i] * sc(z[j]);
        }
    }
    a.truncate(z.len() - 1);
    (q, a)
}
fn vanishing(h: &[F]) -> Vec<F> {
    h.iter()
        .fold(vec![F::one()], |p, x| mul(&p, &[-*x, F::one()]))
}

struct Merkle {
    levels: Vec<Vec<[u8; 32]>>,
    leaves: Vec<Vec<u8>>,
}
fn leaf(v: &[u8]) -> [u8; 32] {
    let mut a = vec![0];
    append(&mut a, v);
    hash(&a)
}
fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut v = vec![1];
    append(&mut v, a);
    append(&mut v, b);
    hash(&v)
}
impl Merkle {
    fn new(leaves: Vec<Vec<u8>>) -> Self {
        assert!(leaves.len().is_power_of_two());
        let mut levels = vec![leaves.iter().map(|v| leaf(v)).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            levels.push(
                levels
                    .last()
                    .unwrap()
                    .chunks(2)
                    .map(|p| node(&p[0], &p[1]))
                    .collect(),
            );
        }
        Self { levels, leaves }
    }
    fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }
    fn open(&self, indices: &BTreeSet<usize>) -> Vec<u8> {
        let mut b = vec![];
        for i in indices {
            append(&mut b, &self.leaves[*i]);
        }
        let mut s = indices.clone();
        for l in &self.levels[..self.levels.len() - 1] {
            for i in &s {
                if !s.contains(&(i ^ 1)) {
                    append(&mut b, &l[i ^ 1]);
                }
            }
            s = s.iter().map(|i| i / 2).collect();
        }
        b
    }
}
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let r = &self.b[self.p..self.p + n];
        self.p += n;
        r
    }
}
fn authenticate(
    r: &mut Reader,
    root: [u8; 32],
    size: usize,
    indices: &BTreeSet<usize>,
    width: usize,
) -> BTreeMap<usize, Vec<u8>> {
    let rows: BTreeMap<_, _> = indices
        .iter()
        .map(|i| (*i, r.take(width).to_vec()))
        .collect();
    let mut h: BTreeMap<_, _> = rows.iter().map(|(i, v)| (*i, leaf(v))).collect();
    let mut len = size;
    while len > 1 {
        let mut next = BTreeMap::new();
        for (i, a) in &h {
            if i % 2 == 1 && h.contains_key(&(i ^ 1)) {
                continue;
            }
            let b = if let Some(b) = h.get(&(i ^ 1)) {
                *b
            } else {
                r.take(32).try_into().unwrap()
            };
            next.insert(i / 2, if i % 2 == 0 { node(a, &b) } else { node(&b, a) });
        }
        h = next;
        len /= 2;
    }
    assert_eq!(h[&0], root);
    rows
}
fn indices(q: &[usize], size: usize) -> BTreeSet<usize> {
    q.iter()
        .flat_map(|i| {
            let a = i % (size / 2);
            [a, a + size / 2]
        })
        .collect()
}
fn queries(t: &[u8], count: usize, size: usize) -> Vec<usize> {
    (0..count)
        .map(|i| {
            let mut a = t.to_vec();
            a.push(254);
            append(&mut a, &u64b(i));
            let b = hash(&a);
            u64::from_le_bytes(b[..8].try_into().unwrap()) as usize % size
        })
        .collect()
}

struct Public {
    n: usize,
    count: usize,
    threshold: u64,
    total: u64,
    registry_total: u64,
    apk: P,
    r: P,
    sig: F,
    msg: Vec<u8>,
    root: [u8; 32],
    dom: Domain,
    z: Vec<F>,
    registry_digest: [u8; 32],
}
fn transcript(p: &Public) -> Vec<u8> {
    let mut t = b"Garg/arbitrary-domain/research/v1".to_vec();
    for x in [
        p.n,
        p.dom.layers[0].len(),
        p.count,
        p.threshold as usize,
        p.total as usize,
    ] {
        append(&mut t, &u64b(x));
    }
    append(&mut t, &p.registry_digest);
    append(&mut t, &p.root);
    append(&mut t, &pb(p.apk));
    append(&mut t, &pb(p.r));
    append(&mut t, &fb(p.sig));
    append(&mut t, &u64b(p.msg.len()));
    append(&mut t, &p.msg);
    t
}
fn sig_challenge(msg: &[u8], r: P) -> F {
    let mut a = b"Garg/Schnorr/v1".to_vec();
    append(&mut a, msg);
    append(&mut a, &pb(r));
    hf(&a)
}
fn norms(d: &Domain, round: usize, n: usize) -> Vec<F> {
    let power = (n >> round) / 2 - 1;
    d.layers[round]
        .iter()
        .map(|x| {
            eval(&d.maps[round].denominator.coeffs, *x)
                .pow([power as u64])
                .inverse()
                .unwrap()
        })
        .collect()
}
fn fold_pair(g0: P, f0: F, g1: P, f1: F, x0: F, x1: F, v0: F, v1: F, c: F) -> (P, F) {
    let inv = (x0 - x1).inverse().unwrap();
    let a = (c - x1) * inv * v0;
    let b = (x0 - c) * inv * v1;
    (g0 * sc(a) + g1 * sc(b), f0 * a + f1 * b)
}
fn pairbytes(g: P, f: F) -> Vec<u8> {
    let mut a = pb(g).to_vec();
    append(&mut a, &fb(f));
    a
}
fn batch(row: &[u8], reg: &[u8], opened: &[u8], x: F, at: F, coeff: &[F]) -> (P, F) {
    let inv = (x - at).inverse().unwrap();
    let mut gs = P::identity();
    let mut fs = F::zero();
    // Order: S, Qlow, QZ, W, B, Qwlow, QwZ, Qbit.
    let items = [
        &reg[..32],
        &row[32..64],
        &row[64..96],
        &reg[32..64],
        &row[..32],
        &row[96..128],
        &row[128..160],
        &row[160..192],
    ];
    for i in 0..8 {
        let shift = if [0, 3, 4].contains(&i) {
            x
        } else {
            x.square()
        };
        let a = (coeff[2 * i] + coeff[2 * i + 1] * shift) * inv;
        if i < 3 {
            gs += (pg(items[i]) - pg(&opened[i * 32..i * 32 + 32])) * sc(a);
        } else {
            fs += (pf(items[i]) - pf(&opened[i * 32..i * 32 + 32])) * a;
        }
    }
    (gs, fs)
}

fn verify_signature(p: &Public) {
    assert_eq!(G * sc(p.sig), p.r + p.apk * sc(sig_challenge(&p.msg, p.r)));
}

fn verify_authorization(p: &Public, proof: &[u8]) {
    assert!(p.threshold > 0 && p.total >= p.threshold && p.total <= p.registry_total);
    let k = p.n.ilog2() as usize;
    let size = p.dom.layers[0].len();
    let mut read = Reader { b: proof, p: 0 };
    let initial: [u8; 32] = read.take(32).try_into().unwrap();
    let mut t = transcript(p);
    append(&mut t, &initial);
    let at = challenge(&mut t, 1);
    let opened = read.take(256);
    append(&mut t, opened);
    let coeff: Vec<_> = (0..16).map(|_| challenge(&mut t, 3)).collect();
    let br = pf(&opened[128..160]);
    let zr = eval(&p.z, at);
    let top = at.pow([(p.n - 1) as u64]);
    assert_eq!(
        pg(&opened[..32]) * sc(br),
        p.apk * sc(top) + pg(&opened[32..64]) + pg(&opened[64..96]) * sc(zr)
    );
    assert_eq!(
        pf(&opened[96..128]) * br,
        F::from(p.total) * top + pf(&opened[160..192]) + pf(&opened[192..224]) * zr
    );
    assert_eq!(br * (F::one() - br), pf(&opened[224..256]) * zr);
    let mut roots = vec![];
    let mut challenges = vec![];
    for j in 0..k {
        challenges.push(challenge(&mut t, 4));
        if j + 1 < k {
            let rt: [u8; 32] = read.take(32).try_into().unwrap();
            append(&mut t, &rt);
            roots.push(rt);
        }
    }
    let final_pair = read.take(64);
    append(&mut t, final_pair);
    let q = queries(&t, p.count, size);
    let ii = indices(&q, size);
    let reg = authenticate(&mut read, p.root, size, &ii, 64);
    let initial_rows = authenticate(&mut read, initial, size, &ii, 192);
    let mut layers = vec![];
    for (j, root) in roots.iter().enumerate() {
        let sz = size >> (j + 1);
        layers.push(authenticate(&mut read, *root, sz, &indices(&q, sz), 64));
    }
    assert_eq!(read.p, proof.len());
    for j in 0..k {
        let sz = size >> j;
        let norm = norms(&p.dom, j, p.n);
        for index in indices(&q, sz).into_iter().filter(|i| *i < sz / 2) {
            let (g0, f0, g1, f1) = if j == 0 {
                let a = batch(
                    &initial_rows[&index],
                    &reg[&index],
                    opened,
                    p.dom.layers[0][index],
                    at,
                    &coeff,
                );
                let b = batch(
                    &initial_rows[&(index + sz / 2)],
                    &reg[&(index + sz / 2)],
                    opened,
                    p.dom.layers[0][index + sz / 2],
                    at,
                    &coeff,
                );
                (a.0, a.1, b.0, b.1)
            } else {
                let a = &layers[j - 1][&index];
                let b = &layers[j - 1][&(index + sz / 2)];
                (pg(&a[..32]), pf(&a[32..]), pg(&b[..32]), pf(&b[32..]))
            };
            let folded = fold_pair(
                g0,
                f0,
                g1,
                f1,
                p.dom.layers[j][index],
                p.dom.layers[j][index + sz / 2],
                norm[index],
                norm[index + sz / 2],
                challenges[j],
            );
            let expected = if j + 1 == k {
                final_pair
            } else {
                &layers[j][&index]
            };
            assert_eq!(pairbytes(folded.0, folded.1), expected);
        }
    }
}

fn millis(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

struct Input {
    n: usize,
    k: usize,
    seed: serde_json::Value,
    weights: Vec<u64>,
    bits: Vec<u8>,
    total: u64,
    threshold: u64,
    registry_total: u64,
    msg: Vec<u8>,
    key_seeds: Vec<[u8; 32]>,
    rng_seed: [u8; 32],
}

fn input() -> Input {
    let raw =
        fs::read(std::env::var("WTAS_BENCH_FIXTURE").expect("WTAS_BENCH_FIXTURE is required"))
            .unwrap();
    let f: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let n = usize::try_from(f["n"].as_u64().unwrap()).unwrap();
    assert!(n.is_power_of_two() && n >= 4);
    let weights: Vec<u64> = f["weights"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    let bits: Vec<u8> = f["participation_bits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect();
    assert_eq!(weights.len(), n);
    assert_eq!(bits.len(), n);
    assert!(weights.iter().all(|w| *w > 0));
    assert!(bits.iter().all(|b| *b <= 1));
    let registry_total = weights
        .iter()
        .try_fold(0u64, |a, w| a.checked_add(*w))
        .unwrap();
    let selected_weight = weights
        .iter()
        .zip(&bits)
        .filter(|(_, b)| **b == 1)
        .try_fold(0u64, |a, (w, _)| a.checked_add(*w))
        .unwrap();
    let k = bits.iter().filter(|b| **b == 1).count();
    assert_eq!(f["k"].as_u64().unwrap() as usize, k);
    assert!(k > 0);
    let total = f["selected_weight"].as_u64().unwrap();
    let threshold = f["threshold"].as_u64().unwrap();
    assert_eq!(selected_weight, total);
    assert!(threshold > 0 && threshold <= total && total <= registry_total);
    let key_seeds: Vec<[u8; 32]> = f["public_benchmark_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .expect("a key seed is 32 bytes")
        })
        .collect();
    assert_eq!(key_seeds.len(), n);
    let rng_seed = hex::decode(f["rng_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("rng seed is 32 bytes");
    let msg = hex::decode(f["message_hex"].as_str().unwrap()).unwrap();
    Input {
        n,
        k,
        seed: f["seed"].clone(),
        weights,
        bits,
        total,
        threshold,
        registry_total,
        msg,
        key_seeds,
        rng_seed,
    }
}

// This function and signing() are the only functions accepting signing secrets.
// The public seeds are reproducible benchmark data, not production private keys.
fn keygen(seeds: &[[u8; 32]]) -> (Vec<F>, Vec<P>) {
    let sk: Vec<F> = seeds
        .iter()
        .map(|seed| {
            let digest = Sha512::digest(seed);
            // Schnorr keys use the scalar field rather than Ed25519 pruning.
            // Wide reduction gives reproducible, negligibly biased field samples.
            F::from_le_bytes_mod_order(&digest)
        })
        .collect();
    let pk = sk.iter().map(|s| G * sc(*s)).collect();
    (sk, pk)
}

struct Signed {
    apk: P,
    r: P,
    sig: F,
    signing_ms: f64,
    signer_mean_ms: f64,
    signer_max_ms: f64,
    coordination_ms: f64,
    share_validation_ms: f64,
    aggregation_core_ms: f64,
}

fn signing(i: &Input, sk: &[F], pk: &[P]) -> Signed {
    let timer = Instant::now();
    let chosen: Vec<usize> = (0..i.n).filter(|j| i.bits[*j] == 1).collect();
    let mut rng = StdRng::from_seed(i.rng_seed);
    let mut coordination_ms = millis(timer);
    let mut signer_times = vec![0.0f64; i.k];
    let mut nonce = Vec::with_capacity(i.k);
    let mut rp = Vec::with_capacity(i.k);
    let mut commits = Vec::with_capacity(i.k);

    // Round 1: each signer creates one nonce and broadcasts its point commitment.
    for actor in 0..i.k {
        let timer = Instant::now();
        let r = pf(&Scalar::random(&mut rng).to_bytes());
        let point = G * sc(r);
        let commitment = hash(&pb(point));
        signer_times[actor] += millis(timer);
        nonce.push(r);
        rp.push(point);
        commits.push(commitment);
    }

    // Round 2: the local coordinator packages openings and computes its view of R.
    // This models CPU work only. It assigns no network-latency value to a round.
    let timer = Instant::now();
    let bulletin: Vec<(usize, [u8; 32], P)> = chosen
        .iter()
        .enumerate()
        .map(|(j, member)| (*member, commits[j], rp[j]))
        .collect();
    let r = bulletin.iter().fold(P::identity(), |sum, row| sum + row.2);
    let c = sig_challenge(&i.msg, r);
    coordination_ms += millis(timer);

    // Round 3: every signer independently checks every opening, reconstructs R,
    // derives the common challenge and returns its own response. Do not charge
    // one coordinator's checks as if all k signers had performed them.
    let mut shares = Vec::with_capacity(i.k);
    for (actor, member) in chosen.iter().enumerate() {
        let timer = Instant::now();
        assert_eq!(bulletin.len(), i.k);
        let mut own_r = P::identity();
        for (j, (identity, commitment, opening)) in bulletin.iter().enumerate() {
            assert_eq!(*identity, chosen[j]);
            let wire = pb(*opening);
            let received = pg(&wire);
            assert_eq!(pb(received), wire);
            assert_eq!(hash(&wire), *commitment);
            own_r += received;
        }
        assert_eq!(bulletin[actor].2, rp[actor]);
        assert_eq!(own_r, r);
        let own_c = sig_challenge(&i.msg, own_r);
        assert_eq!(own_c, c);
        let share = nonce[actor] + own_c * sk[*member];
        signer_times[actor] += millis(timer);
        shares.push(share);
    }

    let timer = Instant::now();
    for (actor, member) in chosen.iter().enumerate() {
        assert_eq!(G * sc(shares[actor]), rp[actor] + pk[*member] * sc(c));
    }
    let share_validation_ms = millis(timer);

    let timer = Instant::now();
    let sig = shares
        .iter()
        .copied()
        .fold(F::zero(), |sum, share| sum + share);
    let apk = chosen
        .iter()
        .fold(P::identity(), |sum, member| sum + pk[*member]);
    let aggregation_core_ms = millis(timer);
    let signing_ms = signer_times.iter().sum::<f64>();
    let signer_mean_ms = signing_ms / i.k as f64;
    let signer_max_ms = signer_times.iter().copied().fold(0.0, f64::max);
    Signed {
        apk,
        r,
        sig,
        signing_ms,
        signer_mean_ms,
        signer_max_ms,
        coordination_ms,
        share_validation_ms,
        aggregation_core_ms,
    }
}

struct Preprocessed {
    bases: Vec<Vec<F>>,
    inverses: Vec<F>,
    s: Vec<P>,
    w: Vec<F>,
    registry: Merkle,
    registry_digest: [u8; 32],
}

// Public-only registry preprocessing: no participation vector or signing secret.
fn preprocess(n: usize, dom: &Domain, z: &[F], pk: &[P], weights: &[u64]) -> Preprocessed {
    let h = &dom.layers[0][..n];
    let mut bases = Vec::with_capacity(n);
    let mut inverses = Vec::with_capacity(n);
    let mut w = vec![F::zero(); n];
    for j in 0..n {
        let (base, remainder) = div(z.to_vec(), &[-h[j], F::one()]);
        assert!(remainder.iter().all(|v| v.is_zero()));
        inverses.push(eval(&base, h[j]).inverse().unwrap());
        for coefficient in 0..n {
            w[coefficient] += base[coefficient] * F::from(weights[j]);
        }
        bases.push(base);
    }
    let s: Vec<P> = (0..n)
        .map(|j| msm(&bases.iter().map(|a| a[j]).collect::<Vec<_>>(), pk))
        .collect();
    let registry = Merkle::new(
        dom.layers[0]
            .iter()
            .map(|x| pairbytes(ep(&s, *x), eval(&w, *x)))
            .collect(),
    );
    let mut digest_input = Vec::new();
    for (j, point) in pk.iter().enumerate() {
        append(&mut digest_input, &pb(*point));
        append(&mut digest_input, &weights[j].to_le_bytes());
    }
    for x in &dom.layers[0] {
        append(&mut digest_input, &fb(*x));
    }
    let registry_digest = hash(&digest_input);
    Preprocessed {
        bases,
        inverses,
        s,
        w,
        registry,
        registry_digest,
    }
}

// All participation-polynomial work starts here, within the proving timer.
// The hidden polynomial s was built only from public group elements in preprocess().
fn prove(p: &Public, pre: &Preprocessed, bits: &[u8]) -> Vec<u8> {
    let n = p.n;
    let size = p.dom.layers[0].len();
    let mut b = vec![F::zero(); n];
    for j in 0..n {
        if bits[j] == 1 {
            for coefficient in 0..n {
                b[coefficient] += pre.bases[j][coefficient] * pre.inverses[j];
            }
        }
    }
    let s = &pre.s;
    let w = &pre.w;
    let registry = &pre.registry;
    let (qz, mut qlow) = pdiv(pmul(s, &b), &p.z);
    qlow[n - 1] -= p.apk;
    assert_eq!(qlow.pop().unwrap(), P::identity());
    let (qwz, mut qwlow) = div(mul(w, &b), &p.z);
    qwlow[n - 1] -= F::from(p.total);
    assert!(qwlow.pop().unwrap().is_zero());
    let mut one_minus: Vec<_> = b.iter().map(|x| -*x).collect();
    one_minus[0] += F::one();
    let (qbit, remainder) = div(mul(&b, &one_minus), &p.z);
    assert!(remainder.iter().all(|x| x.is_zero()));
    assert_eq!(qz.len(), n - 1);
    assert_eq!(qwz.len(), n - 1);
    assert_eq!(qbit.len(), n - 1);
    let initial = Merkle::new(
        p.dom.layers[0]
            .iter()
            .map(|x| {
                let mut row = fb(eval(&b, *x)).to_vec();
                append(&mut row, &pb(ep(&qlow, *x)));
                append(&mut row, &pb(ep(&qz, *x)));
                for a in [&qwlow, &qwz, &qbit] {
                    append(&mut row, &fb(eval(a, *x)));
                }
                row
            })
            .collect(),
    );
    let mut proof = initial.root().to_vec();
    let mut t = transcript(p);
    append(&mut t, &initial.root());
    let at = challenge(&mut t, 1);
    assert!(
        !p.dom.layers[0].contains(&at),
        "unlucky opening challenge: generate a fresh fixture"
    );
    let mut opened = Vec::new();
    for a in [s, &qlow, &qz] {
        append(&mut opened, &pb(ep(a, at)));
    }
    for a in [w, &b, &qwlow, &qwz, &qbit] {
        append(&mut opened, &fb(eval(a, at)));
    }
    append(&mut proof, &opened);
    append(&mut t, &opened);
    let coeff: Vec<_> = (0..16).map(|_| challenge(&mut t, 3)).collect();
    let mut values: Vec<_> = (0..size)
        .map(|j| {
            batch(
                &initial.leaves[j],
                &registry.leaves[j],
                &opened,
                p.dom.layers[0][j],
                at,
                &coeff,
            )
        })
        .collect();
    let mut fri = Vec::new();
    for j in 0..n.ilog2() as usize {
        let c = challenge(&mut t, 4);
        let sz = values.len();
        let norm = norms(&p.dom, j, n);
        let next: Vec<_> = (0..sz / 2)
            .map(|idx| {
                fold_pair(
                    values[idx].0,
                    values[idx].1,
                    values[idx + sz / 2].0,
                    values[idx + sz / 2].1,
                    p.dom.layers[j][idx],
                    p.dom.layers[j][idx + sz / 2],
                    norm[idx],
                    norm[idx + sz / 2],
                    c,
                )
            })
            .collect();
        if j + 1 < n.ilog2() as usize {
            let tree = Merkle::new(next.iter().map(|(g, f)| pairbytes(*g, *f)).collect());
            append(&mut proof, &tree.root());
            append(&mut t, &tree.root());
            fri.push(tree);
        } else {
            assert!(next.iter().all(|v| v == &next[0]));
            let last = pairbytes(next[0].0, next[0].1);
            append(&mut proof, &last);
            append(&mut t, &last);
        }
        values = next;
    }
    let q = queries(&t, p.count, size);
    let ii = indices(&q, size);
    append(&mut proof, &registry.open(&ii));
    append(&mut proof, &initial.open(&ii));
    for (j, tree) in fri.iter().enumerate() {
        append(&mut proof, &tree.open(&indices(&q, size >> (j + 1))));
    }
    proof
}

fn encode_fields(out: &mut Vec<u8>, values: &[F]) {
    append(out, &u64b(values.len()));
    for value in values {
        append(out, &fb(*value));
    }
}

// Explicit research-implementation registry format, NOT a claim about Garg's
// theoretical succinct verification-key size. The domain and maps are included.
fn registry_material(i: &Input, p: &Public, pk: &[P]) -> Vec<u8> {
    let mut out = b"Garg/research/public-registry/v1".to_vec();
    for x in [i.n, p.count] {
        append(&mut out, &u64b(x));
    }
    append(&mut out, &p.threshold.to_le_bytes());
    append(&mut out, &p.registry_total.to_le_bytes());
    append(&mut out, &p.root);
    append(&mut out, &p.registry_digest);
    for (j, point) in pk.iter().enumerate() {
        append(&mut out, &pb(*point));
        append(&mut out, &i.weights[j].to_le_bytes());
    }
    let rounds = i.n.ilog2() as usize;
    append(&mut out, &u64b(rounds));
    for j in 0..rounds {
        encode_fields(&mut out, &p.dom.layers[j]);
        encode_fields(&mut out, &p.dom.maps[j].denominator.coeffs);
    }
    encode_fields(&mut out, &p.z);
    out
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("first argument is output directory");
    let i = input();
    let count = 96;
    let blowup = 16;

    let timer = Instant::now();
    let dom = domain(i.n * blowup);
    let z = vanishing(&dom.layers[0][..i.n]);
    let setup_ms = millis(timer);

    let timer = Instant::now();
    let (sk, pk) = keygen(&i.key_seeds);
    let keygen_ms = millis(timer);

    // Signing is executed serially, so signing_ms is total participant CPU.
    let signed = signing(&i, &sk, &pk);

    let timer = Instant::now();
    let pre = preprocess(i.n, &dom, &z, &pk, &i.weights);
    let p = Public {
        n: i.n,
        count,
        threshold: i.threshold,
        total: i.total,
        registry_total: i.registry_total,
        apk: signed.apk,
        r: signed.r,
        sig: signed.sig,
        msg: i.msg.clone(),
        root: pre.registry.root(),
        dom,
        z,
        registry_digest: pre.registry_digest,
    };
    let registry_binary = registry_material(&i, &p, &pk);
    let hexfields = |a: &[F]| a.iter().map(|x| hex::encode(fb(*x))).collect::<Vec<_>>();
    let registry_json = serde_json::to_vec_pretty(&json!({
        "n": i.n, "queries": count, "blowup": blowup,
        "threshold": i.threshold, "registered_weight": i.registry_total,
        "root": hex::encode(p.root), "digest": hex::encode(p.registry_digest),
        "public_keys": pk.iter().map(|x| hex::encode(pb(*x))).collect::<Vec<_>>(),
        "weights": i.weights,
        "domain": p.dom.layers[..i.n.ilog2() as usize].iter().map(|a| hexfields(a)).collect::<Vec<_>>(),
        "denominators": p.dom.maps[..i.n.ilog2() as usize].iter().map(|a| hexfields(&a.denominator.coeffs)).collect::<Vec<_>>(),
        "vanishing": hexfields(&p.z)
    })).unwrap();
    let preprocessing_ms = millis(timer);

    let timer = Instant::now();
    let proof = prove(&p, &pre, &i.bits);
    let proving_ms = millis(timer);

    let timer = Instant::now();
    let signature_timer = Instant::now();
    verify_signature(&p);
    let signature_verification_ms = millis(signature_timer);
    let proof_timer = Instant::now();
    verify_authorization(&p, &proof);
    let proof_verification_ms = millis(proof_timer);
    let verification_ms = millis(timer);

    let timer = Instant::now();
    // Core package: apk || R || z || exact_total:u64 || proof. Common context
    // and the externally authenticated registry are not included in this count.
    let mut package = Vec::with_capacity(proof.len() + 104);
    append(&mut package, &pb(p.apk));
    append(&mut package, &pb(p.r));
    append(&mut package, &fb(p.sig));
    append(&mut package, &p.total.to_le_bytes());
    append(&mut package, &proof);
    let instance_json = serde_json::to_vec_pretty(&json!({
        "n": i.n, "k": i.k, "seed": i.seed,
        "queries": count, "blowup": blowup, "threshold": i.threshold, "total": i.total,
        "apk": hex::encode(pb(p.apk)), "R": hex::encode(pb(p.r)),
        "signature_scalar": hex::encode(fb(p.sig)), "message": hex::encode(&p.msg),
        "registry_root": hex::encode(p.root), "registry_digest": hex::encode(p.registry_digest)
    }))
    .unwrap();
    let serialization_ms = millis(timer);

    let aggregation_and_proving_ms = signed.coordination_ms
        + signed.share_validation_ms
        + signed.aggregation_core_ms
        + proving_ms
        + serialization_ms;
    let report = json!({
        "scheme": "garg",
        "protocol_version": "garg-arbitrary-domain-reference-timed-v1",
        "n": i.n, "k": i.k, "seed": i.seed, "honest_pass": true,
        "setup_ms": setup_ms, "keygen_ms": keygen_ms,
        "preprocessing_ms": preprocessing_ms,
        "signing_ms": signed.signing_ms,
        "signer_mean_ms": signed.signer_mean_ms, "signer_max_ms": signed.signer_max_ms,
        "coordination_ms": signed.coordination_ms,
        "share_validation_ms": signed.share_validation_ms,
        "aggregation_core_ms": signed.aggregation_core_ms,
        "proving_ms": proving_ms, "serialization_ms": serialization_ms,
        "aggregation_and_proving_ms": aggregation_and_proving_ms,
        "signature_verification_ms": signature_verification_ms,
        "proof_verification_ms": proof_verification_ms,
        "verification_ms": verification_ms,
        "proof_bytes": proof.len(), "signature_core_bytes": 64,
        "core_package_bytes": package.len(),
        "registry_material_bytes": registry_binary.len(),
        "queries": count, "blowup": blowup, "threads_spawned": 0,
        "native_group": "Ristretto255; Garg Schnorr, not Ed25519 signatures",
        "adaptation": "arbitrary-domain weighted-leading-coefficient sums; packed Merkle oracles; degree-tight batched hidden/clear FRI",
        "security": "fixed research parameters, not audited matched-128-bit security",
        "prover": "public-key group-polynomial reference arithmetic, not optimized ECFFT",
        "nonce_model": "fresh sequential draws from a fixture-seeded benchmark RNG; not a production concurrent-signing client",
        "cpu_timing_model": "all selected signers execute locally and serially; no network latency",
        "file_io_in_timing": false
    });
    // Filesystem output and diagnostic printing are outside all reported timers.
    fs::create_dir_all(&out).unwrap();
    fs::write(format!("{out}/proof.bin"), &proof).unwrap();
    fs::write(format!("{out}/core-package.bin"), &package).unwrap();
    fs::write(format!("{out}/public.json"), &instance_json).unwrap();
    fs::write(format!("{out}/registry.bin"), &registry_binary).unwrap();
    fs::write(format!("{out}/registry.json"), &registry_json).unwrap();
    fs::write(
        format!("{out}/result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}
