//! Scalar polynomial routines corresponding to the author's radix-two FFT code.
use blstrs::Scalar;
use ff::{Field, PrimeField};

pub fn invert(x: Scalar) -> Scalar {
    Option::<Scalar>::from(x.invert()).expect("nonzero scalar denominator")
}

pub fn power(x: Scalar, n: usize) -> Scalar {
    x.pow_vartime([n as u64])
}

pub fn root_of_unity(n: usize) -> Scalar {
    assert!(n >= 2 && n.is_power_of_two());
    assert!(n.trailing_zeros() <= Scalar::S);
    // The author gnark domain uses this specific orientation of the 2^32 root.
    let mut root = Option::<Scalar>::from(Scalar::from_bytes_be(&[
        0x16,0xa2,0xa1,0x9e,0xdf,0xe8,0x1f,0x20,0xd0,0x9b,0x68,0x19,0x22,0xc8,0x13,0xb4,
        0xb6,0x36,0x83,0x50,0x8c,0x22,0x80,0xb9,0x38,0x29,0x97,0x1f,0x43,0x9f,0x0d,0x2b,
    ])).unwrap();
    for _ in n.trailing_zeros()..Scalar::S {
        root = root.square();
    }
    root
}

pub fn powers(base: Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut value = Scalar::ONE;
    for _ in 0..n {
        out.push(value);
        value *= base;
    }
    out
}

/// In-place radix-two FFT in natural input/output order.
pub fn fft(values: &mut [Scalar], omega: Scalar, inverse: bool) {
    let n = values.len();
    assert!(n.is_power_of_two());
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
    let generator = if inverse { invert(omega) } else { omega };
    let mut length = 2;
    while length <= n {
        let step = power(generator, n / length);
        for start in (0..n).step_by(length) {
            let mut twiddle = Scalar::ONE;
            for k in 0..length / 2 {
                let a = values[start + k];
                let b = values[start + k + length / 2] * twiddle;
                values[start + k] = a + b;
                values[start + k + length / 2] = a - b;
                twiddle *= step;
            }
        }
        length <<= 1;
    }
    if inverse {
        let inv_n = invert(Scalar::from(n as u64));
        for x in values {
            *x *= inv_n;
        }
    }
}

pub fn interpolate(values: &[Scalar], omega: Scalar) -> Vec<Scalar> {
    let mut out = values.to_vec();
    fft(&mut out, omega, true);
    out
}

pub fn coset_evaluate(coefficients: &[Scalar], omega: Scalar, coset: Scalar) -> Vec<Scalar> {
    let mut out = coefficients.to_vec();
    let mut scale = Scalar::ONE;
    for x in &mut out {
        *x *= scale;
        scale *= coset;
    }
    fft(&mut out, omega, false);
    out
}

pub fn coset_interpolate(values: &[Scalar], omega: Scalar, coset: Scalar) -> Vec<Scalar> {
    let mut out = interpolate(values, omega);
    let inv_coset = invert(coset);
    let mut scale = Scalar::ONE;
    for x in &mut out {
        *x *= scale;
        scale *= inv_coset;
    }
    out
}

/// Montgomery batch inversion, matching gnark's all-roots helper.
pub fn batch_invert(values: &[Scalar]) -> Vec<Scalar> {
    assert!(values.iter().all(|x| !bool::from(x.is_zero())));
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = Scalar::ONE;
    for value in values {
        prefixes.push(product);
        product *= value;
    }
    product = invert(product);
    let mut out = vec![Scalar::ZERO; values.len()];
    for i in (0..values.len()).rev() {
        out[i] = product * prefixes[i];
        product *= values[i];
    }
    out
}

pub fn lagrange_roots_at(roots: &[Scalar], at: Scalar) -> Vec<Scalar> {
    let n = roots.len();
    if let Some(index) = roots.iter().position(|x| *x == at) {
        let mut out = vec![Scalar::ZERO; n];
        out[index] = Scalar::ONE;
        return out;
    }
    let z = power(at, n) - Scalar::ONE;
    let differences: Vec<_> = roots.iter().map(|x| at - x).collect();
    let inv_differences = batch_invert(&differences);
    let mut denominators = Vec::with_capacity(n);
    let mut denominator = Scalar::from(n as u64);
    for _ in 0..n {
        denominators.push(denominator);
        denominator *= roots[n - 1];
    }
    let inv_denominators = batch_invert(&denominators);
    (0..n).map(|i| z * inv_differences[i] * inv_denominators[i]).collect()
}

/// Generic author-style interpolation weights on the (N-1)-point L set.
pub fn lagrange_at(nodes: &[Scalar], at: Scalar) -> Vec<Scalar> {
    if let Some(index) = nodes.iter().position(|x| *x == at) {
        let mut out = vec![Scalar::ZERO; nodes.len()];
        out[index] = Scalar::ONE;
        return out;
    }
    let numerator: Scalar = nodes.iter().map(|x| at - x).product();
    nodes.iter().enumerate().map(|(i, x)| {
        let denominator: Scalar = nodes.iter().enumerate()
            .filter(|(j, _)| *j != i).map(|(_, y)| x - y).product();
        (numerator * invert(at - x)) * invert(denominator)
    }).collect()
}

/// Preserve the author's explicit N^2 denominator work and per-cell divisions.
pub fn batch_lagrange(l: &[Scalar], h: &[Scalar]) -> Vec<Vec<Scalar>> {
    let denominators: Vec<Scalar> = h.iter().enumerate().map(|(i, x)| {
        h.iter().enumerate().filter(|(j, _)| *j != i)
            .map(|(_, y)| x - y).product()
    }).collect();
    l.iter().map(|x| {
        let z = power(*x, h.len()) - Scalar::ONE;
        h.iter().zip(&denominators).map(|(y, denominator)| z * invert((*x - y) * denominator)).collect()
    }).collect()
}
