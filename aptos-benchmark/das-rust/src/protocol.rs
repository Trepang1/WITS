//! Full asymmetric BLS12-381 Das23 author-reference port.
//!
//! The setup retains tau only to reproduce the author's local CRS experiment.
//! Key generation, public preprocessing and proving do not use it as a shortcut.
use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use ff::{Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use sha2::{Digest, Sha256};
use crate::poly;

#[derive(Clone)]
pub struct Crs {
    pub n: usize,
    pub tau: Scalar,
    pub beta: Scalar,
    pub h_scalar: Scalar,
    pub omega: Scalar,
    pub fft_coset: Scalar,
    pub lag_coset: Scalar,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub g1_beta: G1Affine,
    pub g2_beta: G2Affine,
    pub h1: G1Affine,
    pub h2: G2Affine,
    pub h_tau: G2Affine,
    pub h: Vec<Scalar>,
    pub l: Vec<Scalar>,
    pub lag_lh: Vec<Vec<Scalar>>,
    pub z_hl_inv: Scalar,
    pub g2_tau: G2Affine,
    pub v_h_tau: G2Affine,
    pub pot: Vec<G1Affine>,
    pub pot_h: Vec<G1Affine>,
    pub lag_h_tau: Vec<G1Affine>,
    pub lag_h_tau_h: Vec<G1Affine>,
    pub lag2_h_tau: Vec<G2Affine>,
    pub lag_l_tau: Vec<G1Affine>,
    pub g_alpha: G1Affine,
}

pub fn msm(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    assert_eq!(points.len(), scalars.len());
    if points.is_empty() { return G1Projective::identity(); }
    let projective: Vec<_> = points.iter().map(G1Projective::from).collect();
    G1Projective::multi_exp(&projective, scalars)
}

fn fixed_g1(base: G1Affine, scalars: &[Scalar]) -> Vec<G1Affine> {
    // The Go BatchScalarMultiplication API shares fixed-base precomputation.
    // Build it here, inside the timed caller, and still produce every output.
    let width = fixed_window(scalars.len());
    let windows = (Scalar::NUM_BITS as usize + width - 1) / width;
    let stride = (1usize << width) - 1;
    let mut projective_table = Vec::with_capacity(windows * stride);
    let mut shifted = G1Projective::from(base);
    for _ in 0..windows {
        let mut multiple = shifted;
        for _ in 0..stride {
            projective_table.push(multiple);
            multiple += shifted;
        }
        for _ in 0..width { shifted = shifted.double(); }
    }
    let mut table = vec![G1Affine::identity(); projective_table.len()];
    G1Projective::batch_normalize(&projective_table, &mut table);
    let points: Vec<_> = scalars.iter().map(|s| {
        let bytes = s.to_bytes_le();
        let mut point = G1Projective::identity();
        for window in 0..windows {
            let digit = scalar_window(&bytes, window * width, width);
            if digit != 0 { point += table[window * stride + digit - 1]; }
        }
        point
    }).collect();
    let mut out = vec![G1Affine::identity(); points.len()];
    G1Projective::batch_normalize(&points, &mut out);
    out
}

fn fixed_g2(base: G2Affine, scalars: &[Scalar]) -> Vec<G2Affine> {
    let width = fixed_window(scalars.len());
    let windows = (Scalar::NUM_BITS as usize + width - 1) / width;
    let stride = (1usize << width) - 1;
    let mut projective_table = Vec::with_capacity(windows * stride);
    let mut shifted = G2Projective::from(base);
    for _ in 0..windows {
        let mut multiple = shifted;
        for _ in 0..stride {
            projective_table.push(multiple);
            multiple += shifted;
        }
        for _ in 0..width { shifted = shifted.double(); }
    }
    let mut table = vec![G2Affine::identity(); projective_table.len()];
    G2Projective::batch_normalize(&projective_table, &mut table);
    let points: Vec<_> = scalars.iter().map(|s| {
        let bytes = s.to_bytes_le();
        let mut point = G2Projective::identity();
        for window in 0..windows {
            let digit = scalar_window(&bytes, window * width, width);
            if digit != 0 { point += table[window * stride + digit - 1]; }
        }
        point
    }).collect();
    let mut out = vec![G2Affine::identity(); points.len()];
    G2Projective::batch_normalize(&points, &mut out);
    out
}

fn fixed_window(count: usize) -> usize {
    match count { 0..=64 => 4, 65..=256 => 5, _ => 6 }
}

fn scalar_window(bytes: &[u8; 32], start: usize, width: usize) -> usize {
    let position = start / 8;
    let mut value = bytes[position] as u16;
    if position + 1 < bytes.len() { value |= (bytes[position + 1] as u16) << 8; }
    ((value >> (start % 8)) & ((1u16 << width) - 1)) as usize
}

impl Crs {
    pub fn generate(n: usize, scalar_rng: &mut impl FnMut() -> Scalar) -> Self {
        let tau = scalar_rng();
        let beta = scalar_rng();
        let h = scalar_rng();
        Self::from_scalars(n, tau, beta, h, None)
    }

    pub fn from_scalars(n: usize, tau: Scalar, beta: Scalar, h_scalar: Scalar,
                        omega_override: Option<Scalar>) -> Self {
        assert!(n >= 2 && n.is_power_of_two());
        let omega = omega_override.unwrap_or_else(|| poly::root_of_unity(n));
        assert_eq!(poly::power(omega, n), Scalar::ONE);
        assert_ne!(poly::power(omega, n/2), Scalar::ONE);
        assert_ne!(poly::power(tau, n), Scalar::ONE);
        assert!(!bool::from(beta.is_zero()) && !bool::from(h_scalar.is_zero()));
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let g1_beta = (g1 * beta).to_affine();
        let g2_beta = (g2 * beta).to_affine();
        let g2_tau = (g2 * tau).to_affine();
        let h1 = (g1 * h_scalar).to_affine();
        let h2 = (g2 * h_scalar).to_affine();
        let h_tau = (g2 * (tau*h_scalar)).to_affine();
        let h = poly::powers(omega, n);
        let lag_coset = (2..n+2).map(|i| Scalar::from(i as u64))
            .find(|x| poly::power(*x, n) != Scalar::ONE).unwrap();
        let z_hl_inv = poly::invert(poly::power(lag_coset, n) - Scalar::ONE);
        let l: Vec<_> = h[..n-1].iter().map(|x| lag_coset*x).collect();
        let powers = poly::powers(tau, n);
        let pot = fixed_g1(g1.to_affine(), &powers);
        let pot_h = fixed_g1(h1, &powers);
        let v_h_tau = (g2 * (poly::power(tau, n)-Scalar::ONE)).to_affine();
        let lag_h = poly::lagrange_roots_at(&h, tau);
        let lag_l = poly::lagrange_at(&l, tau);
        let lag_h_tau = fixed_g1(g1.to_affine(), &lag_h);
        let lag_h_tau_h = fixed_g1(h1, &lag_h);
        let lag2_h_tau = fixed_g2(g2.to_affine(), &lag_h);
        let lag_l_tau = fixed_g1(g1.to_affine(), &lag_l);
        let alpha: Scalar = lag_h.iter().zip(&h).map(|(a,x)| *a*poly::invert(*x)).sum();
        let g_alpha = (g1*alpha).to_affine();
        let lag_lh = poly::batch_lagrange(&l, &h);
        Self { n,tau,beta,h_scalar,omega,fft_coset:Scalar::from(7),
            lag_coset,g1,g2,g1_beta,g2_beta,h1,h2,h_tau,h,l,lag_lh,z_hl_inv,g2_tau,
            v_h_tau,pot,pot_h,lag_h_tau,lag_h_tau_h,lag2_h_tau,lag_l_tau,g_alpha }
    }
}

#[derive(Clone)]
pub struct Registry {
    pub weights: Vec<u64>,
    pub sk: Vec<Scalar>,
    pub pk: Vec<G1Affine>,
    pub pk_beta: Vec<G1Affine>,
    pub p_comm: G1Affine,
    pub w_tau: G1Affine,
    pub q_tau: Vec<G1Affine>,
    pub h_tau: Vec<G1Affine>,
    pub h_tau_h: Vec<G1Projective>,
    pub l_tau: Vec<Vec<G1Affine>>,
    pub a_tau: Vec<G1Affine>,
}

impl Registry {
    pub fn keygen(crs: &Crs, weights: &[u64], scalar_rng: &mut impl FnMut() -> Scalar) -> Self {
        let secrets: Vec<_> = (0..crs.n).map(|_| scalar_rng()).collect();
        Self::from_secrets(crs, weights, &secrets)
    }

    pub fn from_secrets(crs: &Crs, weights: &[u64], secrets: &[Scalar]) -> Self {
        assert_eq!(weights.len(), crs.n);
        assert_eq!(secrets.len(), crs.n);
        let pk_beta = fixed_g1(crs.g1_beta, secrets);
        // The full (N-1)*N public hint matrix is actually generated.
        let l_tau: Vec<_> = crs.lag_l_tau.iter().map(|base| fixed_g1(*base, secrets)).collect();
        let pk = fixed_g1(crs.g1.to_affine(), secrets);
        let a_tau = fixed_g1(crs.g_alpha, secrets);
        let h_tau_projective: Vec<_> = secrets.iter().enumerate()
            .map(|(i,s)| crs.lag_h_tau[i]*s).collect();
        let h_tau_h: Vec<_> = secrets.iter().enumerate()
            .map(|(i,s)| crs.lag_h_tau_h[i]*s).collect();
        let p_comm = h_tau_projective.iter().copied().sum::<G1Projective>().to_affine();
        let mut h_tau = vec![G1Affine::identity();crs.n];
        G1Projective::batch_normalize(&h_tau_projective,&mut h_tau);
        Self { weights:weights.to_vec(),sk:secrets.to_vec(),pk,pk_beta,p_comm,
            w_tau:G1Affine::identity(),q_tau:vec![],h_tau,h_tau_h,l_tau,a_tau }
    }

    pub fn preprocess(&mut self, crs: &Crs) {
        let lag_ls: Vec<_> = (0..crs.n-1)
            .map(|l| msm(&self.l_tau[l], &crs.lag_lh[l])).collect();
        let mut q_tau_projective = Vec::with_capacity(crs.n);
        for i in 0..crs.n {
            let bases: Vec<_> = (0..crs.n-1)
                .map(|l| lag_ls[l]-self.l_tau[l][i]).collect();
            let exponents: Vec<_> = (0..crs.n-1)
                .map(|l| crs.lag_lh[l][i]*crs.z_hl_inv).collect();
            let mut affine = vec![G1Affine::identity();bases.len()];
            G1Projective::batch_normalize(&bases,&mut affine);
            q_tau_projective.push(msm(&affine,&exponents));
        }
        let weights: Vec<_> = self.weights.iter().map(|w| Scalar::from(*w)).collect();
        self.w_tau=msm(&crs.lag_h_tau,&weights).to_affine();
        self.q_tau=vec![G1Affine::identity();crs.n];
        G1Projective::batch_normalize(&q_tau_projective,&mut self.q_tau);
    }
}

pub fn hash_message(message: &[u8]) -> G2Affine {
    G2Projective::hash_to_curve(message, &[], &[]).to_affine()
}

pub fn sign(message: &[u8], secret: Scalar) -> G2Projective {
    hash_message(message)*secret
}

/// Actual multi-Miller loop and final exponentiation, mirroring one Go Pair API.
pub fn pair_product(g1: &[G1Affine], g2: &[G2Affine]) -> Gt {
    assert_eq!(g1.len(),g2.len());
    let prepared: Vec<_> = g2.iter().copied().map(G2Prepared::from).collect();
    let pairs: Vec<_> = g1.iter().zip(&prepared).collect();
    Bls12::multi_miller_loop(&pairs).final_exponentiation()
}

pub fn check_share(crs: &Crs, message_point: G2Affine, signature: G2Projective, key: G1Affine) -> bool {
    pair_product(&[key,(-crs.g1).to_affine()],&[message_point,signature.to_affine()])==Gt::identity()
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub weight: u64,
    pub b_tau: G1Affine,
    pub b_neg_tau: G2Affine,
    pub q_tau: G1Affine,
    pub r_tau: G1Affine,
    pub q_b: G1Affine,
    pub p_tau: G1Affine,
    pub agg_pk: G1Affine,
    pub agg_pk_b: G1Affine,
    pub agg_sig: G2Affine,
}

pub fn fs_challenge(registry: &Registry, b_tau: G1Affine, agg_pk: G1Affine, weight: u64) -> Scalar {
    assert!(weight<=u32::MAX as u64);
    let mut hash=Sha256::new();
    hash.update(b"Das23/WTS/HFS/v1\0");
    for point in [registry.p_comm,registry.w_tau,b_tau,agg_pk] { hash.update(point.to_compressed()); }
    hash.update((weight as u32).to_le_bytes());
    // gnark fr.SetBytes reads a big-endian integer and reduces modulo r.
    hash.finalize().iter().fold(Scalar::ZERO,|acc,b|acc*Scalar::from(256)+Scalar::from(*b as u64))
}

fn binary_proof(crs: &Crs, selected: &[usize]) -> G1Affine {
    let mut bits=vec![Scalar::ZERO;crs.n];
    for i in selected { bits[*i]=Scalar::ONE; }
    let neg: Vec<_> = bits.iter().map(|b|Scalar::ONE-b).collect();
    let b=poly::coset_evaluate(&poly::interpolate(&bits,crs.omega),crs.omega,crs.fft_coset);
    let bn=poly::coset_evaluate(&poly::interpolate(&neg,crs.omega),crs.omega,crs.fft_coset);
    let den=poly::invert(poly::power(crs.fft_coset,crs.n)-Scalar::ONE);
    let quotient: Vec<_> = b.iter().zip(&bn).map(|(x,y)|x*y*den).collect();
    msm(&crs.pot,&poly::coset_interpolate(&quotient,crs.omega,crs.fft_coset)).to_affine()
}

fn weights_proof(crs: &Crs, registry: &Registry, selected: &[usize]) -> (G1Projective,G1Projective,G1Projective) {
    let mut bits=vec![Scalar::ZERO;crs.n];
    let weights: Vec<_> = registry.weights.iter().map(|w|Scalar::from(*w)).collect();
    let mut selected_weights=vec![Scalar::ZERO;crs.n];
    for i in selected { bits[*i]=Scalar::ONE; selected_weights[*i]=weights[*i]; }
    let b=poly::coset_evaluate(&poly::interpolate(&bits,crs.omega),crs.omega,crs.fft_coset);
    let w=poly::coset_evaluate(&poly::interpolate(&weights,crs.omega),crs.omega,crs.fft_coset);
    let r=poly::coset_evaluate(&poly::interpolate(&selected_weights,crs.omega),crs.omega,crs.fft_coset);
    let den=poly::invert(poly::power(crs.fft_coset,crs.n)-Scalar::ONE);
    let quotient: Vec<_> = (0..crs.n).map(|i|(b[i]*w[i]-r[i])*den).collect();
    let quotient=poly::coset_interpolate(&quotient,crs.omega,crs.fft_coset);
    let remainder=poly::coset_interpolate(&r,crs.omega,crs.fft_coset);
    (msm(&crs.pot,&quotient),msm(&crs.pot[..crs.n-1],&remainder[1..]),msm(&crs.pot_h,&remainder))
}

fn secret_proof(crs: &Crs, registry: &Registry, selected: &[usize]) -> G1Projective {
    let lag_zero=poly::lagrange_roots_at(&crs.h,Scalar::ZERO);
    let exponents: Vec<_> = selected.iter().map(|i|lag_zero[*i]).collect();
    let bases: Vec<_> = selected.iter().map(|i|registry.a_tau[*i]).collect();
    let second=msm(&bases,&exponents);
    let exponents: Vec<_> = selected.iter().map(|i|poly::invert(crs.h[*i])).collect();
    let bases: Vec<_> = selected.iter().map(|i|registry.h_tau[*i]).collect();
    msm(&bases,&exponents)-second
}

pub fn combine(crs: &Crs, registry: &Registry, selected: &[usize], signatures: &[G2Projective]) -> Signature {
    assert_eq!(selected.len(),signatures.len());
    assert!(selected.windows(2).all(|pair|pair[0]<pair[1]));
    let mut b_tau=G1Projective::identity();
    let mut b2_tau=G2Projective::identity();
    let mut q_tau=G1Projective::identity();
    let mut agg_pk=G1Projective::identity();
    let mut agg_pk_b=G1Projective::identity();
    let mut p_tau=G1Projective::identity();
    let mut weight=0u64;
    for i in selected {
        assert!(*i<crs.n);
        b_tau+=crs.lag_h_tau[*i];
        b2_tau+=crs.lag2_h_tau[*i];
        q_tau+=registry.q_tau[*i];
        agg_pk+=registry.pk[*i];
        agg_pk_b+=registry.pk_beta[*i];
        p_tau+=registry.h_tau_h[*i];
        weight=weight.checked_add(registry.weights[*i]).expect("weight overflow");
    }
    let b_neg_tau=(crs.g2-b2_tau).to_affine();
    let agg_sig=signatures.iter().copied().sum::<G2Projective>().to_affine();
    let q_b=binary_proof(crs,selected);
    let (qw_tau,rw_tau,pw_tau_h)=weights_proof(crs,registry,selected);
    let mut r_tau=secret_proof(crs,registry,selected);
    let b_tau=b_tau.to_affine();
    let agg_pk=agg_pk.to_affine();
    let xi=fs_challenge(registry,b_tau,agg_pk,weight);
    q_tau+=qw_tau*xi;
    r_tau+=rw_tau*xi;
    p_tau+=pw_tau_h*xi;
    Signature { weight,b_tau,b_neg_tau,q_tau:q_tau.to_affine(),r_tau:r_tau.to_affine(),q_b,
        p_tau:p_tau.to_affine(),agg_pk,agg_pk_b:agg_pk_b.to_affine(),agg_sig }
}

pub fn verify(crs: &Crs, registry: &Registry, message: &[u8], sigma: &Signature, threshold: u64) -> bool {
    let g1=crs.g1.to_affine();
    let g2=crs.g2.to_affine();
    let ng1=(-crs.g1).to_affine();
    let ng2=(-crs.g2).to_affine();
    let mut result=pair_product(&[sigma.agg_pk,ng1],&[hash_message(message),sigma.agg_sig])==Gt::identity();
    let n_inv=poly::invert(Scalar::from(crs.n as u64));
    let g_n_inv=(crs.g2*n_inv).to_affine();
    let h_n_inv=(crs.h2*n_inv).to_affine();
    // Maintain the author's API grouping: nine final exponentiations, 15 pairs.
    result &= pair_product(&[sigma.agg_pk,sigma.agg_pk_b],&[crs.g2_beta,ng2])==Gt::identity();
    let complement=(crs.g1-sigma.b_tau).to_affine();
    result &= pair_product(&[complement,ng1],&[g2,sigma.b_neg_tau])==Gt::identity();
    let binary_lhs=pair_product(&[sigma.b_tau],&[sigma.b_neg_tau]);
    let binary_rhs=pair_product(&[sigma.q_b],&[crs.v_h_tau]);
    result &= binary_lhs==binary_rhs;
    let b2_tau=(crs.g2-sigma.b_neg_tau).to_affine();
    let xi=fs_challenge(registry,sigma.b_tau,sigma.agg_pk,sigma.weight);
    let o_tau=(registry.w_tau*xi+registry.p_comm).to_affine();
    let mu=(crs.g1*(xi*Scalar::from(sigma.weight))+sigma.agg_pk).to_affine();
    let inner_lhs=pair_product(&[o_tau],&[b2_tau]);
    let inner_rhs=pair_product(&[sigma.q_tau,sigma.r_tau,mu],&[crs.v_h_tau,crs.g2_tau,g_n_inv]);
    result &= inner_lhs==inner_rhs;
    let degree_lhs=pair_product(&[sigma.p_tau],&[g2]);
    let degree_rhs=pair_product(&[sigma.r_tau,mu],&[crs.h_tau,h_n_inv]);
    result &= degree_lhs==degree_rhs;
    result && threshold<=sigma.weight
}
