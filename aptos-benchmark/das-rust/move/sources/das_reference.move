/// Complete corrected-author Das23 WTS verifier using native BLS12-381 algebra.
/// Public preprocessing is registered by the authenticated benchmark authority.
/// The 536-byte package and Fiat--Shamir transcript match the Go/Rust wrapper.
module bench::das_reference {
    use std::vector;
    use std::option;
    use std::signer;
    use std::bcs;
    use std::hash;
    use aptos_std::from_bcs;
    use aptos_std::crypto_algebra::{Self as a, Element};
    use aptos_std::bls12381_algebra::{G1, G2, Gt, Fr,
        FormatG1Compr, FormatG2Compr, FormatFrLsb, HashG2XmdSha256SswuRo};

    const FR_ORDER: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    struct Parameters has key, drop {
        n: u64,
        threshold: u64,
        // pComm,wTau in G1; betaG2,hG2,h*tauG2,tauG2,Z_H(tau)G2 in G2.
        public_points: vector<vector<u8>>
    }

    struct Proof has drop {
        apk: Element<G1>,
        sig: Element<G2>,
        total: u64,
        b_tau: Element<G1>,
        b_neg_tau: Element<G2>,
        q_tau: Element<G1>,
        r_tau: Element<G1>,
        q_b: Element<G1>,
        p_tau: Element<G1>,
        apk_beta: Element<G1>
    }

    fun slice(input: &vector<u8>, offset: u64, size: u64): vector<u8> {
        assert!(offset + size <= vector::length(input), 100);
        let result = vector[];
        let i = 0;
        while (i < size) {
            vector::push_back(&mut result, *vector::borrow(input, offset + i));
            i = i + 1;
        };
        result
    }

    fun g1(bytes: &vector<u8>): Element<G1> {
        option::destroy_some(a::deserialize<G1, FormatG1Compr>(bytes))
    }

    fun g2(bytes: &vector<u8>): Element<G2> {
        option::destroy_some(a::deserialize<G2, FormatG2Compr>(bytes))
    }

    fun decode(wire: &vector<u8>): Proof {
        assert!(vector::length(wire) == 536, 101);
        Proof {
            apk: g1(&slice(wire, 0, 48)),
            sig: g2(&slice(wire, 48, 96)),
            total: from_bcs::to_u64(slice(wire, 144, 8)),
            b_tau: g1(&slice(wire, 152, 48)),
            b_neg_tau: g2(&slice(wire, 200, 96)),
            q_tau: g1(&slice(wire, 296, 48)),
            r_tau: g1(&slice(wire, 344, 48)),
            q_b: g1(&slice(wire, 392, 48)),
            p_tau: g1(&slice(wire, 440, 48)),
            apk_beta: g1(&slice(wire, 488, 48))
        }
    }

    /// Same domain, compressed points, uint32LE weight, SHA-256, and reduction
    /// as corrected Go getFSChal. The supported fixture range fits uint32.
    fun challenge(p: &Parameters, wire: &vector<u8>, total: u64): Element<Fr> {
        let input = b"Das23/WTS/HFS/v1\x00";
        vector::append(&mut input, *vector::borrow(&p.public_points, 0));
        vector::append(&mut input, *vector::borrow(&p.public_points, 1));
        vector::append(&mut input, slice(wire, 152, 48));
        vector::append(&mut input, slice(wire, 0, 48));
        vector::append(&mut input, bcs::to_bytes(&(total as u32)));
        let digest = hash::sha2_256(input);
        vector::reverse(&mut digest);
        let value = from_bcs::to_u256(digest) % FR_ORDER;
        option::destroy_some(a::deserialize<Fr, FormatFrLsb>(&bcs::to_bytes(&value)))
    }

    public entry fun register(owner: &signer, n: u64, threshold: u64,
        public_points: vector<vector<u8>>) acquires Parameters {
        assert!(signer::address_of(owner) == @bench, 102);
        assert!(n >= 2 && ((n & (n - 1)) == 0) && threshold > 0, 103);
        assert!(vector::length(&public_points) == 7, 104);
        let _p_comm = g1(vector::borrow(&public_points, 0));
        let _w_tau = g1(vector::borrow(&public_points, 1));
        let i = 2;
        while (i < 7) {
            let _point = g2(vector::borrow(&public_points, i));
            i = i + 1;
        };
        let p = Parameters { n, threshold, public_points };
        if (exists<Parameters>(@bench)) {
            *borrow_global_mut<Parameters>(@bench) = p;
        } else {
            move_to(owner, p);
        };
    }

    fun signature(proof: &Proof, message: &vector<u8>, gen1: &Element<G1>) {
        let hashed = a::hash_to<G2, HashG2XmdSha256SswuRo>(&vector[], message);
        let negative = a::neg<G1>(gen1);
        let target = a::multi_pairing<G1, G2, Gt>(
            &vector[proof.apk, negative], &vector[hashed, proof.sig]);
        assert!(a::eq<Gt>(&target, &a::zero<Gt>()), 201);
    }

    fun key_and_complement(proof: &Proof, beta_g2: &Element<G2>,
        gen1: &Element<G1>, gen2: &Element<G2>) {
        let target = a::multi_pairing<G1, G2, Gt>(
            &vector[proof.apk, proof.apk_beta],
            &vector[*beta_g2, a::neg<G2>(gen2)]);
        assert!(a::eq<Gt>(&target, &a::zero<Gt>()), 202);
        let complement = a::sub<G1>(gen1, &proof.b_tau);
        let target = a::multi_pairing<G1, G2, Gt>(
            &vector[complement, a::neg<G1>(gen1)],
            &vector[*gen2, proof.b_neg_tau]);
        assert!(a::eq<Gt>(&target, &a::zero<Gt>()), 203);
    }

    fun binary(proof: &Proof, v_h_tau: &Element<G2>) {
        let lhs = a::pairing<G1, G2, Gt>(&proof.b_tau, &proof.b_neg_tau);
        let rhs = a::pairing<G1, G2, Gt>(&proof.q_b, v_h_tau);
        assert!(a::eq<Gt>(&lhs, &rhs), 204);
    }

    fun inner_product(proof: &Proof, o_tau: &Element<G1>, mu: &Element<G1>,
        v_h_tau: &Element<G2>, tau_g2: &Element<G2>,
        n_inv_g2: &Element<G2>, gen2: &Element<G2>) {
        let b2_tau = a::sub<G2>(gen2, &proof.b_neg_tau);
        let lhs = a::pairing<G1, G2, Gt>(o_tau, &b2_tau);
        let rhs = a::multi_pairing<G1, G2, Gt>(
            &vector[proof.q_tau, proof.r_tau, *mu],
            &vector[*v_h_tau, *tau_g2, *n_inv_g2]);
        assert!(a::eq<Gt>(&lhs, &rhs), 205);
    }

    fun degree_and_weight(proof: &Proof, mu: &Element<G1>,
        h_tau_g2: &Element<G2>, n_inv_h2: &Element<G2>,
        gen2: &Element<G2>, threshold: u64) {
        let lhs = a::pairing<G1, G2, Gt>(&proof.p_tau, gen2);
        let rhs = a::multi_pairing<G1, G2, Gt>(
            &vector[proof.r_tau, *mu], &vector[*h_tau_g2, *n_inv_h2]);
        assert!(a::eq<Gt>(&lhs, &rhs), 206);
        assert!(threshold <= proof.total, 207);
    }

    /// Complete gverify: 9 native pairing API calls over 15 input pairs.
    /// The N-dependent material is public registration, not a free input hint.
    public entry fun verify(_owner: &signer, message: vector<u8>, wire: vector<u8>)
        acquires Parameters {
        let p = borrow_global<Parameters>(@bench);
        let proof = decode(&wire);
        let p_comm = g1(vector::borrow(&p.public_points, 0));
        let w_tau = g1(vector::borrow(&p.public_points, 1));
        let beta_g2 = g2(vector::borrow(&p.public_points, 2));
        let h2 = g2(vector::borrow(&p.public_points, 3));
        let h_tau_g2 = g2(vector::borrow(&p.public_points, 4));
        let tau_g2 = g2(vector::borrow(&p.public_points, 5));
        let v_h_tau = g2(vector::borrow(&p.public_points, 6));
        let gen1 = a::one<G1>();
        let gen2 = a::one<G2>();
        signature(&proof, &message, &gen1);
        let n_inv = option::destroy_some(a::inv<Fr>(&a::from_u64<Fr>(p.n)));
        let n_inv_g2 = a::scalar_mul<G2, Fr>(&gen2, &n_inv);
        let n_inv_h2 = a::scalar_mul<G2, Fr>(&h2, &n_inv);
        key_and_complement(&proof, &beta_g2, &gen1, &gen2);
        binary(&proof, &v_h_tau);
        let xi = challenge(p, &wire, proof.total);
        let o_tau = a::add<G1>(&a::scalar_mul<G1, Fr>(&w_tau, &xi), &p_comm);
        let xi_total = a::mul<Fr>(&xi, &a::from_u64<Fr>(proof.total));
        let mu = a::add<G1>(&a::scalar_mul<G1, Fr>(&gen1, &xi_total), &proof.apk);
        inner_product(&proof, &o_tau, &mu, &v_h_tau, &tau_g2, &n_inv_g2, &gen2);
        degree_and_weight(&proof, &mu, &h_tau_g2, &n_inv_h2, &gen2, p.threshold);
    }
}
