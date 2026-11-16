use blstrs::Scalar;
use ff::Field;
use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha256};

// Public fixture stream matching the corrected author's Go benchmark.
// This is solely for reproducible research inputs.
pub struct ResearchRng {
    seed: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    offset: usize,
    montgomery_inverse: Scalar,
}

impl ResearchRng {
    pub fn new(seed: Vec<u8>) -> Self {
        let q=BigUint::parse_bytes(b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",16).unwrap();
        let radix=(BigUint::one()<<256usize)%&q;
        let inverse=radix.modpow(&(&q-BigUint::from(2u32)),&q).to_bytes_le();
        let mut bytes=[0u8;32];bytes[..inverse.len()].copy_from_slice(&inverse);
        Self {seed,counter:0,buffer:vec![],offset:0,montgomery_inverse:Option::<Scalar>::from(Scalar::from_bytes_le(&bytes)).unwrap()}
    }
    fn read32(&mut self) -> [u8;32] {
        let mut out=[0u8;32];
        for byte in &mut out {
            if self.offset==self.buffer.len() {
                let mut hash=Sha256::new();hash.update(&self.seed);hash.update(self.counter.to_be_bytes());
                self.counter+=1;self.buffer=hash.finalize().to_vec();self.offset=0;
            }
            *byte=self.buffer[self.offset];self.offset+=1;
        }
        out
    }
    pub fn scalar(&mut self) -> Scalar {
        loop {
            let mut bytes=self.read32();bytes[31]&=0x7f;
            if let Some(value)=Option::<Scalar>::from(Scalar::from_bytes_le(&bytes)) {
                // gnark-crypto v0.9.1 samples canonical-range values directly
                // into Montgomery limbs. Match its resulting mathematical value.
                return value*self.montgomery_inverse;
            }
        }
    }
}
