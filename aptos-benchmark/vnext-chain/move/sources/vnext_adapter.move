/// Checked public coordinate conversion, not hash-to-group or a second key.
module bench::vnext_adapter {
    use std::vector;
    use std::bcs;
    use std::option;
    use aptos_std::from_bcs;
    use aptos_std::ristretto255 as r;
    use aptos_std::aptos_hash as hash;

    const P: u256 = 57896044618658097711785492504343953926634992332820282019728792003956564819949;
    const MASK: u256 = 57896044618658097711785492504343953926634992332820282019728792003956564819967;
    const LOW: u256 = 340282366920938463463374607431768211455;
    const LOW127: u256 = 170141183460469231731687303715884105727;
    const D: u256 = 37095705934669439343138083508754565189542113879843219016388785533085940283555;
    const SQRT_M1: u256 = 19681161376707505956807079304988542015446066515923890162744021073123829784752;
    const INV_SQRT_A_D: u256 = 54469307008909316920995813868745141605393597292927456921205312896311721017578;

    struct Point has copy, drop { x: u256, y: u256, z: u256, t: u256 }

    public fun slice(b: &vector<u8>, start: u64, size: u64): vector<u8> {
        assert!(start + size <= vector::length(b), 1);
        vector::slice(b, start, start + size)
    }
    public fun integer(b: &vector<u8>, start: u64): u256 {
        assert!(start + 32 <= vector::length(b), 2);
        from_bcs::to_u256(vector::slice(b, start, start + 32))
    }
    fun reduce(a: u256): u256 {
        let out = (a & MASK) + 19 * (a >> 255);
        if (out >= P) out - P else out
    }
    fun add(a: u256, b: u256): u256 { let c = a + b; if (c >= P) c - P else c }
    fun sub(a: u256, b: u256): u256 { if (a >= b) a - b else P - (b - a) }
    fun neg(a: u256): u256 { if (a == 0) 0 else P - a }
    fun shift128(a: u256): u256 { reduce(((a & LOW127) << 128) + 19 * (a >> 127)) }
    fun mul(a: u256, b: u256): u256 {
        let al = a & LOW;
        let ah = a >> 128;
        let bl = b & LOW;
        let bh = b >> 128;
        add(add(reduce(al * bl), shift128(al * bh)), add(shift128(ah * bl), shift128(shift128(ah * bh))))
    }
    fun square(a: u256): u256 { mul(a, a) }

    fun point(ed: &vector<u8>, x: u256): Point {
        assert!(vector::length(ed) == 32 && x < P, 3);
        let enc = integer(ed, 0);
        let y = enc & MASK;
        assert!(y < P && (x & 1) == (enc >> 255), 4);
        let xx = square(x);
        let yy = square(y);
        assert!(sub(yy, xx) == add(1, mul(D, mul(xx, yy))), 5);
        Point { x, y, z: 1, t: mul(x, y) }
    }
    fun double(p: Point): Point {
        let aa = square(sub(p.y, p.x));
        let bb = square(add(p.y, p.x));
        let cc = mul(add(D, D), square(p.t));
        let dd = add(square(p.z), square(p.z));
        let e = sub(bb, aa);
        let f = sub(dd, cc);
        let g = add(dd, cc);
        let h = add(bb, aa);
        Point { x: mul(e, f), y: mul(g, h), z: mul(f, g), t: mul(e, h) }
    }
    fun encode(p: Point, invsqrt: u256): vector<u8> {
        assert!(invsqrt < P, 6);
        if (p.x == 0 && p.y == p.z) { assert!(invsqrt == 0, 7); return bcs::to_bytes(&0u256) };
        let u1 = mul(add(p.z, p.y), sub(p.z, p.y));
        let u2 = mul(p.x, p.y);
        assert!(mul(square(invsqrt), mul(u1, square(u2))) == 1 && (invsqrt & 1) == 0, 8);
        let i1 = mul(invsqrt, u1);
        let i2 = mul(invsqrt, u2);
        let zi = mul(mul(i1, i2), p.t);
        let x = p.x;
        let y = p.y;
        let den = i2;
        if ((mul(p.t, zi) & 1) == 1) {
            x = mul(p.y, SQRT_M1);
            y = mul(p.x, SQRT_M1);
            den = mul(i1, INV_SQRT_A_D);
        };
        if ((mul(x, zi) & 1) == 1) { y = neg(y); };
        let s = mul(den, sub(p.z, y));
        if ((s & 1) == 1) { s = neg(s); };
        bcs::to_bytes(&s)
    }

    /// Hint = x(P) || encoding(Q) || x(Q) || inverse-sqrt(P), Q with [8]Q=P.
    /// Curve membership, canonical encoding, and the [8] image are all checked.
    /// Since #E=8q, the latter establishes that P is in the prime-order subgroup.
    public fun convert(ed: &vector<u8>, hint: &vector<u8>): vector<u8> {
        assert!(vector::length(hint) == 128, 9);
        let p = point(ed, integer(hint, 0));
        let q = point(&slice(hint, 32, 32), integer(hint, 64));
        let eight = double(double(double(q)));
        assert!(eight.z != 0 && mul(p.x, eight.z) == eight.x && mul(p.y, eight.z) == eight.y, 10);
        encode(p, integer(hint, 96))
    }

    public entry fun check(ed: vector<u8>, hint: vector<u8>, expected: vector<u8>) {
        let actual = convert(&ed, &hint);
        assert!(actual == expected, 11);
        let mapped = option::destroy_some(r::new_point_from_bytes(actual));
        assert!(r::point_to_bytes(&r::point_compress(&mapped)) == expected, 12);
    }

    /// Recompute the reference prover's exact try-and-increment map. Every
    /// rejected candidate is justified by noncanonicality or a nonsquare
    /// witness (2 is a nonsquare in F_p). No prover-selected counter is trusted.
    public fun hash_group(label: vector<u8>, hints: &vector<u8>, ed: &vector<u8>, conversion: &vector<u8>): vector<u8> {
        let mapped = convert(ed, conversion);
        let target = point(ed, integer(conversion, 0));
        assert!(target.x != 0 || target.y != 1, 13);
        let count = vector::length(hints) / 32;
        assert!(count > 0 && count <= 64 && vector::length(hints) == count * 32, 14);
        let counter = 0;
        while (counter < count) {
            let input = b"WTAS/CPU/Edwards/HashToGroup/v1";
            vector::append(&mut input, copy label);
            vector::append(&mut input, bcs::to_bytes(&counter));
            let digest = hash::sha2_512(input);
            let candidate = slice(&digest, 0, 32);
            let enc = integer(&candidate, 0);
            let y = enc & MASK;
            if (y < P) {
                let u = sub(square(y), 1);
                let v = add(mul(D, square(y)), 1);
                let x = integer(hints, counter * 32);
                assert!(x < P, 15);
                let vx2 = mul(v, square(x));
                if (vx2 == u) {
                    if (!(x == 0 && (enc >> 255) == 1)) {
                        let q = point(&candidate, x);
                        let eight = double(double(double(q)));
                        if (!(eight.x == 0 && eight.y == eight.z)) {
                            assert!(counter + 1 == count && eight.z != 0, 16);
                            assert!(mul(target.x, eight.z) == eight.x && mul(target.y, eight.z) == eight.y, 17);
                            return mapped
                        };
                    };
                } else {
                    assert!(v != 0 && u != 0 && vx2 == add(u, u), 18);
                };
            };
            counter = counter + 1;
        };
        abort 19
    }
}
