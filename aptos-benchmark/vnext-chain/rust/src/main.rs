//! Current manuscript WTAS: Edwards keys, fresh dual nonces, statement H,
//! A -> lambda -> shifted S, four commitment points, current IPA convention.
//! A reproducible honest CPU experiment, not a production signing service.
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint as P},
    scalar::Scalar as S,
    traits::{Identity, IsIdentity, VartimeMultiscalarMul},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{fs, time::Instant};

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn hash(b: &[u8]) -> [u8; 64] {
    Sha512::digest(b).into()
}
fn enc(p: &P) -> [u8; 32] {
    p.compress().to_bytes()
}
fn scalar(rng: &mut StdRng) -> S {
    let mut b = [0; 64];
    rng.fill_bytes(&mut b);
    S::from_bytes_mod_order_wide(&b)
}
fn msm(s: &[S], p: &[P]) -> P {
    assert_eq!(s.len(), p.len());
    P::vartime_multiscalar_mul(s, p)
}
fn dot(a: &[S], b: &[S]) -> S {
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}
fn powers(x: S, n: usize) -> Vec<S> {
    let mut a = S::ONE;
    (0..n)
        .map(|_| {
            let r = a;
            a *= x;
            r
        })
        .collect()
}
fn point(label: &[u8]) -> P {
    for i in 0u64.. {
        let mut h = Sha512::new();
        h.update(b"WTAS/CPU/Edwards/HashToGroup/v1");
        h.update(label);
        h.update(i.to_le_bytes());
        let d = h.finalize();
        let b: [u8; 32] = d[..32].try_into().unwrap();
        if let Some(p) = CompressedEdwardsY(b).decompress() {
            if enc(&p) == b {
                let p = p.mul_by_cofactor();
                if !p.is_identity() {
                    return p;
                }
            }
        }
    }
    unreachable!()
}
#[derive(Clone)]
struct T(Vec<u8>);
impl T {
    fn put(&mut self, l: &[u8], v: &[u8]) {
        self.0.extend((l.len() as u32).to_le_bytes());
        self.0.extend(l);
        self.0.extend((v.len() as u64).to_le_bytes());
        self.0.extend(v);
    }
    fn p(&mut self, l: &[u8], p: &P) {
        self.put(l, &enc(p));
    }
    fn s(&mut self, l: &[u8], s: S) {
        self.put(l, &s.to_bytes());
    }
    fn c(&mut self, l: &[u8]) -> S {
        for i in 0u64.. {
            let mut t = self.clone();
            t.put(b"challenge-label", l);
            t.put(b"counter", &i.to_le_bytes());
            let d = hash(&t.0);
            let mut b: [u8; 32] = d[..32].try_into().unwrap();
            b[31] &= 31;
            if let Some(s) = Option::<S>::from(S::from_canonical_bytes(b)) {
                if s != S::ZERO {
                    self.s(l, s);
                    return s;
                }
            }
        }
        unreachable!()
    }
}
struct Params {
    g: Vec<P>,
    h: Vec<P>,
}
fn parameters(n: usize) -> Params {
    let mut used = std::collections::HashSet::new();
    used.insert(enc(&G));
    let mut derive = |family: &str| -> Vec<P> {
        (0..n)
            .map(|i| {
                for retry in 0u64.. {
                    let label = if retry == 0 {
                        format!("{family}/{i}")
                    } else {
                        format!("{family}/{i}/retry/{retry}")
                    };
                    let p = point(label.as_bytes());
                    if used.insert(enc(&p)) {
                        return p;
                    }
                }
                unreachable!()
            })
            .collect()
    };
    let g = derive("g");
    let h = derive("h");
    Params { g, h }
}
struct Registry {
    pk: Vec<P>,
    weighted: Vec<P>,
    w: Vec<u64>,
    digest: [u8; 32],
}
struct Inst {
    m: Vec<u8>,
    r: P,
    s: S,
    k: P,
    threshold: u64,
    total: u64,
}
struct Proof {
    a: P,
    s: P,
    t1: P,
    t2: P,
    tau: S,
    mu: S,
    that: S,
    lr: Vec<(P, P)>,
    af: S,
    bf: S,
}
fn statement(reg: &Registry, v: &Inst) -> T {
    let mut t = T(vec![]);
    t.put(b"protocol", b"WTAS/CPU/current-vNext/1");
    t.put(b"parameter-id", b"Edwards25519-SHA512-253bit-rejection/1");
    t.put(b"registry-digest", &reg.digest);
    t.put(b"registry-version", &1u64.to_le_bytes());
    t.put(b"N", &(reg.pk.len() as u64).to_le_bytes());
    t.put(b"m", &v.m);
    t.p(b"R", &v.r);
    t.s(b"signature-scalar", v.s);
    t.p(b"K", &v.k);
    t.put(b"threshold", &v.threshold.to_le_bytes());
    t.put(b"selected-weight", &v.total.to_le_bytes());
    t
}
fn transcript(p: &Params, reg: &Registry, v: &Inst) -> (T, P) {
    let stmt = statement(reg, v);
    let mut t = T(vec![]);
    t.put(b"WT-Proof", &stmt.0);
    for i in 0u64.. {
        let mut input = b"WT-Blinding-Generator".to_vec();
        input.extend(&stmt.0);
        input.extend(i.to_le_bytes());
        let h = point(&input);
        if h != G && !p.g.contains(&h) && !p.h.contains(&h) {
            t.p(b"H", &h);
            return (t, h);
        }
    }
    unreachable!()
}
fn ipa_u(t: &mut T, p: &Params, h: P) -> P {
    for retry in 0u64.. {
        let mut label = b"WT-IPA-Generator".to_vec();
        label.extend(&t.0);
        if retry != 0 {
            label.extend(retry.to_le_bytes());
        }
        let u = point(&label);
        if u != G && u != h && !p.g.contains(&u) && !p.h.contains(&u) {
            t.p(b"U", &u);
            return u;
        }
    }
    unreachable!()
}
fn evaluated(t: &mut T, q: &Proof, p: &Params, h: P) -> P {
    t.s(b"tau_x", q.tau);
    t.s(b"mu", q.mu);
    t.s(b"t_hat", q.that);
    ipa_u(t, p, h)
}
fn prove(p: &Params, reg: &Registry, v: &Inst, b: &[S], rng: &mut StdRng) -> Proof {
    let n = b.len();
    let (mut t, h) = transcript(p, reg, v);
    let alpha = scalar(rng);
    let rho = scalar(rng);
    let sl: Vec<_> = (0..n).map(|_| scalar(rng)).collect();
    let sr: Vec<_> = (0..n).map(|_| scalar(rng)).collect();
    let bm: Vec<_> = b.iter().map(|x| x - S::ONE).collect();
    let mut q = Proof {
        a: alpha * h + msm(b, &p.g) + msm(&bm, &p.h),
        s: P::identity(),
        t1: P::identity(),
        t2: P::identity(),
        tau: S::ZERO,
        mu: S::ZERO,
        that: S::ZERO,
        lr: vec![],
        af: S::ZERO,
        bf: S::ZERO,
    };
    t.p(b"A", &q.a);
    let lambda = t.c(b"lambda_key");
    let mut gp: Vec<_> = (0..n).map(|i| p.g[i] + lambda * reg.weighted[i]).collect();
    q.s = rho * h + msm(&sl, &gp) + msm(&sr, &p.h);
    t.p(b"S", &q.s);
    let y = t.c(b"y");
    let z = t.c(b"z");
    let yp = powers(y, n);
    let l0: Vec<_> = b.iter().map(|x| x - z).collect();
    let r0: Vec<_> = (0..n)
        .map(|i| yp[i] * (b[i] - S::ONE + z) + z * z * S::from(reg.w[i]))
        .collect();
    let ysr: Vec<_> = (0..n).map(|i| yp[i] * sr[i]).collect();
    let tau1 = scalar(rng);
    let tau2 = scalar(rng);
    q.t1 = (dot(&sl, &r0) + dot(&l0, &ysr)) * G + tau1 * h;
    q.t2 = dot(&sl, &ysr) * G + tau2 * h;
    t.p(b"T1", &q.t1);
    t.p(b"T2", &q.t2);
    let x = t.c(b"x");
    let mut l: Vec<_> = (0..n).map(|i| l0[i] + x * sl[i]).collect();
    let mut r: Vec<_> = (0..n).map(|i| r0[i] + x * ysr[i]).collect();
    q.that = dot(&l, &r);
    q.tau = x * tau1 + x * x * tau2;
    q.mu = alpha + x * rho;
    let u = evaluated(&mut t, &q, p, h);
    let yi = powers(y.invert(), n);
    let mut hp: Vec<_> = (0..n).map(|i| yi[i] * p.h[i]).collect();
    while l.len() > 1 {
        let half = l.len() / 2;
        let left = dot(&l[..half], &r[half..]) * u
            + msm(&l[..half], &gp[half..])
            + msm(&r[half..], &hp[..half]);
        let right = dot(&l[half..], &r[..half]) * u
            + msm(&l[half..], &gp[..half])
            + msm(&r[..half], &hp[half..]);
        t.put(b"round", &(q.lr.len() as u64 + 1).to_le_bytes());
        t.p(b"L", &left);
        t.p(b"R", &right);
        let c = t.c(b"u");
        let ci = c.invert();
        q.lr.push((left, right));
        l = (0..half).map(|i| c * l[i] + ci * l[half + i]).collect();
        r = (0..half).map(|i| ci * r[i] + c * r[half + i]).collect();
        gp = (0..half).map(|i| ci * gp[i] + c * gp[half + i]).collect();
        hp = (0..half).map(|i| c * hp[i] + ci * hp[half + i]).collect();
    }
    q.af = l[0];
    q.bf = r[0];
    q
}
fn verify(p: &Params, reg: &Registry, v: &Inst, q: &Proof) -> bool {
    let n = reg.pk.len();
    if q.lr.len() != n.ilog2() as usize
        || v.threshold == 0
        || v.total < v.threshold
        || v.total > reg.w.iter().sum::<u64>()
        || v.k.is_identity()
    {
        return false;
    }
    let (mut t, h) = transcript(p, reg, v);
    t.p(b"A", &q.a);
    let lambda = t.c(b"lambda_key");
    t.p(b"S", &q.s);
    let y = t.c(b"y");
    let z = t.c(b"z");
    let yp = powers(y, n);
    let delta = (z - z * z) * yp.iter().sum::<S>() - z * z * z * S::from(reg.w.iter().sum::<u64>());
    t.p(b"T1", &q.t1);
    t.p(b"T2", &q.t2);
    let x = t.c(b"x");
    if q.that * G + q.tau * h != (z * z * S::from(v.total) + delta) * G + x * q.t1 + x * x * q.t2 {
        return false;
    }
    let u = evaluated(&mut t, q, p, h);
    let mut coeff = vec![S::ONE];
    let mut lr = P::identity();
    for (j, (l, r)) in q.lr.iter().enumerate() {
        t.put(b"round", &(j as u64 + 1).to_le_bytes());
        t.p(b"L", l);
        t.p(b"R", r);
        let c = t.c(b"u");
        let ci = c.invert();
        coeff = coeff.iter().flat_map(|a| [a * ci, a * c]).collect();
        lr += c * c * l + ci * ci * r;
    }
    let gp: Vec<_> = (0..n).map(|i| p.g[i] + lambda * reg.weighted[i]).collect();
    let yi = powers(y.invert(), n);
    let hp: Vec<_> = (0..n).map(|i| yi[i] * p.h[i]).collect();
    let reversed: Vec<_> = coeff.iter().rev().copied().collect();
    let weights: Vec<_> = reg.w.iter().map(|w| z * z * S::from(*w)).collect();
    let target = q.a + x * q.s - z * gp.iter().sum::<P>()
        + z * p.h.iter().sum::<P>()
        + msm(&weights, &hp)
        + lambda * v.k;
    q.af * q.bf * u + q.af * msm(&coeff, &gp) + q.bf * msm(&reversed, &hp)
        == target - q.mu * h + q.that * u + lr
}
fn serialize(q: &Proof) -> Vec<u8> {
    let mut b = vec![];
    for p in [q.a, q.s, q.t1, q.t2] {
        b.extend(enc(&p));
    }
    for s in [q.tau, q.mu, q.that] {
        b.extend(s.to_bytes());
    }
    for (l, r) in &q.lr {
        b.extend(enc(l));
        b.extend(enc(r));
    }
    b.extend(q.af.to_bytes());
    b.extend(q.bf.to_bytes());
    b
}
fn decode_point(b: &[u8]) -> P {
    let a: [u8; 32] = b.try_into().unwrap();
    let p = CompressedEdwardsY(a).decompress().unwrap();
    assert_eq!(enc(&p), a);
    assert!(p.is_torsion_free());
    p
}
fn decode_scalar(b: &[u8]) -> S {
    Option::<S>::from(S::from_canonical_bytes(b.try_into().unwrap())).unwrap()
}
fn decode(b: &[u8], n: usize) -> Proof {
    let ell = n.ilog2() as usize;
    assert_eq!(b.len(), 32 * (9 + 2 * ell));
    let ps: Vec<_> = b[..128].chunks_exact(32).map(decode_point).collect();
    let ss: Vec<_> = b[128..224].chunks_exact(32).map(decode_scalar).collect();
    let lr = b[224..224 + 64 * ell]
        .chunks_exact(64)
        .map(|x| (decode_point(&x[..32]), decode_point(&x[32..])))
        .collect();
    Proof {
        a: ps[0],
        s: ps[1],
        t1: ps[2],
        t2: ps[3],
        tau: ss[0],
        mu: ss[1],
        that: ss[2],
        lr,
        af: decode_scalar(&b[224 + 64 * ell..256 + 64 * ell]),
        bf: decode_scalar(&b[256 + 64 * ell..]),
    }
}
fn ed_c(r: P, k: P, m: &[u8]) -> S {
    let mut b = enc(&r).to_vec();
    b.extend(enc(&k));
    b.extend(m);
    S::from_bytes_mod_order_wide(&hash(&b))
}
fn sig_encode(r: P, s: S) -> Vec<u8> {
    let mut b = enc(&r).to_vec();
    b.extend(s.to_bytes());
    b
}
fn sig_verify(k: P, m: &[u8], b: &[u8]) -> bool {
    if b.len() != 64 || k.is_identity() || !k.is_torsion_free() {
        return false;
    }
    let r = decode_point(&b[..32]);
    let s = decode_scalar(&b[32..]);
    s * G == r + ed_c(r, k, m) * k
}
fn auth_sign(sk: S, m: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let r = scalar(rng);
    let rp = r * G;
    sig_encode(rp, r + ed_c(rp, sk * G, m) * sk)
}
fn binding(m: &[u8], ctx: &[u8], index: usize) -> S {
    let mut t = T(vec![]);
    t.put(b"domain", b"WTAS/binding/1");
    t.put(b"i", &(index as u64).to_le_bytes());
    t.put(b"m", m);
    t.put(b"Bctx", ctx);
    S::from_bytes_mod_order_wide(&hash(&t.0))
}
fn main() {
    let fixture: Value =
        serde_json::from_slice(&fs::read(std::env::var("WTAS_BENCH_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let out = std::env::args().nth(1).unwrap();
    let n = fixture["n"].as_u64().unwrap() as usize;
    let chosen: Vec<usize> = fixture["participation_bits"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, x)| x.as_u64() == Some(1))
        .map(|(i, _)| i)
        .collect();
    let k = chosen.len();
    let mut rng = StdRng::from_seed(
        hex::decode(fixture["rng_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let now = Instant::now();
    let p = parameters(n);
    let setup_ms = ms(now);
    let now = Instant::now();
    let sk: Vec<S> = fixture["public_benchmark_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let seed = hex::decode(x.as_str().unwrap()).unwrap();
            let d = hash(&seed);
            let mut s: [u8; 32] = d[..32].try_into().unwrap();
            s[0] &= 248;
            s[31] &= 63;
            s[31] |= 64;
            S::from_bytes_mod_order(s)
        })
        .collect();
    let pk: Vec<_> = sk.iter().map(|s| s * G).collect();
    let combiner_sk = scalar(&mut rng);
    let combiner_pk = combiner_sk * G;
    let keygen_ms = ms(now);
    let now = Instant::now();
    let w: Vec<u64> = fixture["weights"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    let mut reg_bytes = vec![];
    let mut pops = vec![];
    for i in 0..n {
        assert!(!pk[i].is_identity() && pk[i].is_torsion_free());
        let d = scalar(&mut rng);
        let dp = d * G;
        let mut pop = T(vec![]);
        pop.put(b"domain", b"WTAS/PoP/1");
        pop.put(b"i", &(i as u64).to_le_bytes());
        pop.p(b"pk", &pk[i]);
        pop.put(b"w", &w[i].to_le_bytes());
        pop.p(b"D", &dp);
        let e = pop.c(b"e");
        let response = d + e * sk[i];
        assert_eq!(response * G, dp + e * pk[i]);
        pops.push(json!({"D":hex::encode(enc(&dp)),"response":hex::encode(response.to_bytes())}));
        reg_bytes.extend(enc(&pk[i]));
        reg_bytes.extend(w[i].to_le_bytes());
        reg_bytes.extend(enc(&p.g[i]));
        reg_bytes.extend(enc(&p.h[i]));
    }
    let weighted: Vec<_> = (0..n).map(|i| S::from(w[i]) * pk[i]).collect();
    let reg = Registry {
        pk,
        weighted,
        w,
        digest: hash(&reg_bytes)[..32].try_into().unwrap(),
    };
    let preprocessing_ms = ms(now);
    let m = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
    let total = fixture["selected_weight"].as_u64().unwrap();
    let threshold = fixture["threshold"].as_u64().unwrap();
    let mut signer_times = vec![0.0; k];
    let mut nonces = vec![];
    let mut commitments = vec![];
    for (j, i) in chosen.iter().enumerate() {
        let now = Instant::now();
        let mut pair = vec![];
        for domain in [b"WTAS/nonce/r/1".as_slice(), b"WTAS/nonce/e/1".as_slice()] {
            let mut zeta = [0; 32];
            rng.fill_bytes(&mut zeta);
            let mut h = Sha512::new();
            h.update(domain);
            h.update(zeta);
            h.update(sk[*i].to_bytes());
            let digest: [u8; 64] = h.finalize().into();
            pair.push(S::from_bytes_mod_order_wide(&digest));
        }
        let rp = pair[0] * G;
        let ep = pair[1] * G;
        commitments.push((rp, ep));
        nonces.push((pair[0], pair[1]));
        signer_times[j] += ms(now);
    }
    let now = Instant::now();
    let mut ctx = vec![];
    for (j, i) in chosen.iter().enumerate() {
        assert!(*i < n && (j == 0 || chosen[j - 1] < *i));
        let _ = decode_point(&enc(&commitments[j].0));
        let _ = decode_point(&enc(&commitments[j].1));
        ctx.extend((*i as u64).to_le_bytes());
        ctx.extend(enc(&commitments[j].0));
        ctx.extend(enc(&commitments[j].1));
        ctx.extend(reg.w[*i].to_le_bytes());
        ctx.extend(enc(&reg.pk[*i]));
    }
    // Reconstruct independently in the coordinator role; no signer-side cache
    // or fixture-supplied weight total substitutes for this work.
    let coordinator_rho: Vec<_> = chosen.iter().map(|i| binding(&m, &ctx, *i)).collect();
    let mut coordinator_coeff = vec![];
    let mut coordinator_points = vec![];
    for (j, (rp, ep)) in commitments.iter().enumerate() {
        coordinator_coeff.extend([S::ONE, coordinator_rho[j]]);
        coordinator_points.extend([*rp, *ep]);
    }
    let r = msm(&coordinator_coeff, &coordinator_points);
    let key = chosen.iter().map(|i| reg.weighted[*i]).sum::<P>();
    let recomputed_total = chosen
        .iter()
        .try_fold(0u64, |a, i| a.checked_add(reg.w[*i]))
        .unwrap();
    assert_eq!(total, recomputed_total);
    assert!(recomputed_total >= threshold && !key.is_identity());
    let total = recomputed_total;
    let c = ed_c(r, key, &m);
    let coordination_ms = ms(now);
    let mut responses = vec![];
    for (j, i) in chosen.iter().enumerate() {
        let now = Instant::now();
        // Every signer processes the received canonical list, rather than trusting
        // coordinator-owned points or sharing decoded state across participants.
        let mut received = vec![];
        let mut last = None;
        let mut received_weight = 0u64;
        for entry in ctx.chunks_exact(112) {
            let index = u64::from_le_bytes(entry[..8].try_into().unwrap()) as usize;
            assert!(index < n && last.map_or(true, |x| index > x));
            last = Some(index);
            let rp = decode_point(&entry[8..40]);
            let ep = decode_point(&entry[40..72]);
            let weight = u64::from_le_bytes(entry[72..80].try_into().unwrap());
            assert_eq!(weight, reg.w[index]);
            assert_eq!(&entry[80..112], enc(&reg.pk[index]));
            received_weight = received_weight.checked_add(weight).unwrap();
            received.push((index, rp, ep));
        }
        assert_eq!(received.len(), k);
        assert_eq!(received[j].0, *i);
        assert_eq!(received[j].1, commitments[j].0);
        assert_eq!(received[j].2, commitments[j].1);
        assert!(received_weight >= threshold);
        let rho: Vec<_> = received
            .iter()
            .map(|(i, _, _)| binding(&m, &ctx, *i))
            .collect();
        let mut coeff = vec![];
        let mut pts = vec![];
        for (q, (_, rp, ep)) in received.iter().enumerate() {
            coeff.extend([S::ONE, rho[q]]);
            pts.extend([*rp, *ep]);
        }
        let r = msm(&coeff, &pts);
        let key = received.iter().map(|(i, _, _)| reg.weighted[*i]).sum::<P>();
        assert!(!key.is_identity());
        let c = ed_c(r, key, &m);
        let share = nonces[j].0 + rho[j] * nonces[j].1 + c * S::from(reg.w[*i]) * sk[*i];
        responses.push(share);
        nonces[j] = (S::ZERO, S::ZERO);
        signer_times[j] += ms(now);
    }
    let signing_ms = signer_times.iter().sum::<f64>();
    let now = Instant::now();
    for (j, i) in chosen.iter().enumerate() {
        let rho = binding(&m, &ctx, *i);
        assert_eq!(
            responses[j] * G,
            commitments[j].0 + rho * commitments[j].1 + c * reg.weighted[*i]
        );
    }
    let share_validation_ms = ms(now);
    let now = Instant::now();
    let s = responses.iter().sum::<S>();
    let v = Inst {
        m,
        r,
        s,
        k: key,
        threshold,
        total,
    };
    let aggregation_core_ms = ms(now);
    let bits: Vec<_> = fixture["participation_bits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| S::from(x.as_u64().unwrap()))
        .collect();
    let now = Instant::now();
    let proof = prove(&p, &reg, &v, &bits, &mut rng);
    let proving_ms = ms(now);
    let now = Instant::now();
    let bytes = serialize(&proof);
    let serialization_ms = ms(now);
    assert_eq!(bytes.len(), 32 * (9 + 2 * n.ilog2() as usize));
    let signature = sig_encode(r, s);
    let mut package = statement(&reg, &v).0;
    package.extend(&bytes);
    let now = Instant::now();
    let auth = auth_sign(combiner_sk, &package, &mut rng);
    let combiner_auth_sign_ms = ms(now);
    let now = Instant::now();
    let decoded = decode(&bytes, n);
    let decode_ms = ms(now);
    let now = Instant::now();
    assert!(sig_verify(key, &v.m, &signature));
    let signature_verification_ms = ms(now);
    let now = Instant::now();
    assert!(verify(&p, &reg, &v, &decoded));
    let proof_verification_ms = ms(now);
    let now = Instant::now();
    assert!(sig_verify(combiner_pk, &package, &auth));
    let combiner_auth_verify_ms = ms(now);
    let verification_ms =
        decode_ms + signature_verification_ms + proof_verification_ms + combiner_auth_verify_ms;
    let agg = coordination_ms
        + share_validation_ms
        + aggregation_core_ms
        + proving_ms
        + serialization_ms
        + combiner_auth_sign_ms;
    fs::create_dir_all(&out).unwrap();
    fs::write(format!("{out}/proof.bin"), &bytes).unwrap();
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

    fs::write(format!("{out}/ed25519-check.json"),serde_json::to_vec_pretty(&json!({"public_key":hex::encode(enc(&key)),"message":hex::encode(&v.m),"signature":hex::encode(&signature),"combiner_public_key":hex::encode(enc(&combiner_pk)),"combiner_message":hex::encode(&package),"combiner_signature":hex::encode(&auth)})).unwrap()).unwrap();
    let report = json!({"scheme":"ours","protocol_version":"current-vNext-20261026","n":n,"k":k,"seed":fixture["seed"],"honest_pass":true,"setup_ms":setup_ms,"keygen_ms":keygen_ms,"preprocessing_ms":preprocessing_ms,"signing_ms":signing_ms,"signer_mean_ms":signing_ms/k as f64,"signer_max_ms":signer_times.iter().copied().fold(0.0,f64::max),"coordination_ms":coordination_ms,"share_validation_ms":share_validation_ms,"aggregation_core_ms":aggregation_core_ms,"proving_ms":proving_ms,"serialization_ms":serialization_ms,"aggregation_and_proving_ms":agg,"proof_decode_ms":decode_ms,"signature_verification_ms":signature_verification_ms,"proof_verification_ms":proof_verification_ms,"combiner_auth_sign_ms":combiner_auth_sign_ms,"combiner_auth_verify_ms":combiner_auth_verify_ms,"verification_ms":verification_ms,"proof_bytes":bytes.len(),"signature_core_bytes":64,"core_package_bytes":bytes.len()+64+32+8+64,"full_statement_and_proof_bytes":package.len()+auth.len(),"registry_material_bytes":reg_bytes.len()+n*32,"signature_primitive":"Ed25519-compatible fresh dual nonce; Edwards25519","network_timing":false,"production_rng":false,"signer_context":"Each signer independently reconstructs all binding factors and aggregate nonce; no cross-signer memoization"});
    fs::write(
        format!("{out}/result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", report);
}
